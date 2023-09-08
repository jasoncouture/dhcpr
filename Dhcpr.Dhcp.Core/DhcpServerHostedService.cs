using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

using Dhcpr.Core;
using Dhcpr.Core.Queue;
using Dhcpr.Dhcp.Core.Client;
using Dhcpr.Dhcp.Core.Pipeline;
using Dhcpr.Dhcp.Core.Protocol;

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Dhcpr.Dhcp.Core;

public sealed class DhcpServerHostedService : BackgroundService
{
    private readonly ILogger<DhcpServerHostedService> _logger;
    private readonly IMessageQueue<QueuedDhcpMessage> _processingQueue;
    private readonly UdpClient _client = new();

    public DhcpServerHostedService(
        ILogger<DhcpServerHostedService> logger,
        IMessageQueue<QueuedDhcpMessage> processingQueue)
    {
        _logger = logger;
        _processingQueue = processingQueue;
    }


    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var dhcpServerSocket = _client;

        dhcpServerSocket.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.PacketInformation, true);
        dhcpServerSocket.Client.Bind(Constants.ServerEndpoint);
        dhcpServerSocket.Client.EnableBroadcast = true;
        var buffer = new byte[16384];

        while (!stoppingToken.IsCancellationRequested)
        {
            var receiveResult = await dhcpServerSocket.Client.ReceiveMessageFromAsync(buffer, Constants.ServerEndpoint)
                .ConfigureAwait(false);
            var bufferSlice = buffer[..receiveResult.ReceivedBytes];
            if (!DhcpMessage.TryParse(bufferSlice, out var dhcpMessage))
            {
                _logger.LogWarning("Ignoring invalid DHCP packet: {packet}",
                    string.Join(':', bufferSlice.Select(i => i.ToString("X2"))));
                if (receiveResult.ReceivedBytes == buffer.Length)
                {
                    _logger.LogWarning(
                        "Request message may have failed to parse because it's too big. The datagram we received was {size} bytes long, which is the maximum we accept.",
                        receiveResult.ReceivedBytes
                    );
                }

                continue;
            }

            if (!TryGetNetworkInformation(receiveResult.PacketInformation.Interface, out var localAddress,
                    out var subnetMask, out var broadcastAddress, out var interfaceName))
            {
                _logger.LogWarning(
                    "Unable to get local network interface for interface index: {index}, cannot process DHCP packet.",
                    receiveResult.PacketInformation.Interface);
                continue;
            }

            var networkInfo = new DhcpNetworkInformation(new IPNetwork(localAddress, subnetMask, broadcastAddress),
                receiveResult.PacketInformation.Interface, interfaceName);
            var context = new DhcpRequestContext()
            {
                Message = dhcpMessage,
                NetworkInformation = networkInfo,
                Cancel = false,
                Response = null
            };
            _processingQueue.Enqueue(new QueuedDhcpMessage(dhcpServerSocket, context), stoppingToken);
        }
    }

    private bool TryGetNetworkInformation(
        int interfaceIndex,
        out IPAddress address,
        out IPAddress networkMask,
        out IPAddress networkBroadcastAddress,
        [NotNullWhen(true)] out string? interfaceName)
    {
        address = networkMask = networkBroadcastAddress = IPAddress.Any;
        interfaceName = null;
        var interfaces = NetworkInterface.GetAllNetworkInterfaces();
        NetworkInterface? matchingInterface = null;
        IPInterfaceProperties? matchingProperties = null;
        foreach (var networkInterface in interfaces)
        {
            if (!networkInterface.Supports(NetworkInterfaceComponent.IPv4)) continue;
            var ipv4Properties = networkInterface.GetIPProperties().GetIPv4Properties();
            if (ipv4Properties.Index != interfaceIndex) continue;
            matchingInterface = networkInterface;
            matchingProperties = networkInterface.GetIPProperties();
        }

        if (matchingInterface == null || matchingProperties == null) return false;
        interfaceName = matchingInterface.Name;
        var unicastAddress =
            matchingProperties.UnicastAddresses.FirstOrDefault(i =>
                i.Address.AddressFamily == AddressFamily.InterNetwork);
        if (unicastAddress is null) return false;
        address = unicastAddress.Address;
        networkMask = unicastAddress.IPv4Mask;
        Span<byte> networkMaskAddressBytes = stackalloc byte[4];
        Span<byte> addressBytes = stackalloc byte[4];
        Span<byte> broadcastAddressBytes = stackalloc byte[4];
        networkMask.TryWriteBytes(networkMaskAddressBytes, out _);
        address.TryWriteBytes(addressBytes, out _);
        var integerNetMask = BitConverter.ToUInt32(networkMaskAddressBytes).ToHostByteOrder();
        integerNetMask ^= uint.MaxValue;
        BitConverter.TryWriteBytes(networkMaskAddressBytes, integerNetMask.ToNetworkByteOrder());

        for (var x = 0; x < 4; x++)
        {
            broadcastAddressBytes[x] = (byte)(addressBytes[x] | networkMaskAddressBytes[x]);
        }

        networkBroadcastAddress = new IPAddress(broadcastAddressBytes);
        return true;
    }
}