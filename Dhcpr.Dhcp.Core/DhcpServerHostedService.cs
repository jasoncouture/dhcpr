using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

using Dhcpr.Core;
using Dhcpr.Dhcp.Core.Pipeline;
using Dhcpr.Dhcp.Core.Protocol;

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Dhcpr.Dhcp.Core;

public class DhcpServerHostedService : BackgroundService
{
    private readonly ILogger<DhcpServerHostedService> _logger;
    private readonly IEnumerable<IDhcpRequestHandler> _interceptors;
    private readonly UdpClient _client = new();
    private const int DhcpServerPort = 67;
    private const int DhcpClientPort = 68;

    public DhcpServerHostedService(ILogger<DhcpServerHostedService> logger,
        IEnumerable<IDhcpRequestHandler> interceptors)
    {
        _logger = logger;
        _interceptors = interceptors;
    }


    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var dhcpServerSocket = _client;
        var listenEndPoint = new IPEndPoint(IPAddress.Any, DhcpServerPort);
        dhcpServerSocket.Client.EnableBroadcast = true;
        dhcpServerSocket.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.PacketInformation, true);
        dhcpServerSocket.Client.Bind(listenEndPoint);
        var buffer = new byte[16384];
        var tasks = new List<Task>();

        while (!stoppingToken.IsCancellationRequested)
        {
            var receiveResult = await dhcpServerSocket.Client.ReceiveMessageFromAsync(buffer, listenEndPoint)
                .ConfigureAwait(false);
            var bufferSlice = buffer[..receiveResult.ReceivedBytes];
            _logger.LogInformation("Got a {length} byte packet, trying to parse it as a DHCP Message",
                receiveResult.ReceivedBytes);
            if (!DhcpMessage.TryParse(bufferSlice, out var dhcpMessage))
            {
                _logger.LogWarning("Unable to parse DHCP packet: {packet}",
                    string.Join(':', bufferSlice.Select(i => i.ToString("X2"))));
                return;
            }

            if (!TryGetNetworkInformation(receiveResult.PacketInformation.Interface, out var localAddress,
                    out var subnetMask, out var broadcastAddress, out var interfaceName))
            {
                _logger.LogWarning(
                    "Unable to get local network interface for interface index: {index}, cannot process DHCP packet.",
                    receiveResult.PacketInformation.Interface);
                continue;
            }

            var networkInfo = new DhcpNetworkInformation(localAddress, subnetMask, broadcastAddress,
                receiveResult.PacketInformation.Interface);
            var context = new DhcpRequestContext()
            {
                Message = dhcpMessage, NetworkInformation = networkInfo, Response = null
            };


            tasks.Add(ProcessDhcpContextAsync(context, stoppingToken));
            while (tasks.Any(i => i.IsCompleted))
            {
                tasks.Remove(await Task.WhenAny(tasks));
            }
        }

        if (tasks.Any())
            await Task.WhenAll(tasks);
    }

    private async Task ProcessDhcpContextAsync(DhcpRequestContext requestContext, CancellationToken cancellationToken)
    {
        try
        {
            using (_logger.BeginScope("{macAddress}", requestContext.Message.ClientHardwareAddress))
            using (_logger.BeginScope("{network}", requestContext.NetworkInformation))
            {
                _logger.LogInformation("Processing DHCP message");
                foreach (var processingModule in _interceptors)
                {
                    try
                    {
                        await processingModule.HandleDhcpRequest(requestContext, cancellationToken);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex,
                            "Module fault in processing module: {moduleName}, will attempt to continue",
                            processingModule.GetType().Name);
                    }
                }

                await EncodeAndSendAsync(requestContext, cancellationToken);
            }
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Something went wrong when processing a DHCP message for {macAddress}, here's the network information: {networkInfo}",
                requestContext.Message.ClientHardwareAddress, requestContext.NetworkInformation);
        }
    }

    private async Task EncodeAndSendAsync(DhcpRequestContext requestContext, CancellationToken cancellationToken)
    {
        if (requestContext.Response is null)
        {
            _logger.LogInformation(
                "No interceptors provided a response DHCP message, no response will be sent.");
            return;
        }

        var targetAddress = requestContext.NetworkInformation.BroadcastAddress;
        if (!requestContext.Message.ClientAddress.Equals(IPAddress.Any) &&
            !requestContext.Message.Flags.HasFlag(DhcpFlags.Broadcast))
        {
            targetAddress = requestContext.Message.ClientAddress;
        }

        var targetEndPoint = new IPEndPoint(targetAddress, DhcpClientPort);
        var outboundBuffer = ArrayPool<byte>.Shared.Rent(requestContext.Response.Size);
        try
        {
            outboundBuffer.Initialize();
            requestContext.Response.EncodeTo(outboundBuffer);
            await _client.SendAsync(
                outboundBuffer
                    .AsMemory(0, requestContext.Response.Size),
                targetEndPoint,
                cancellationToken
            );
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(outboundBuffer);
        }
    }

    private bool TryGetNetworkInformation(
        int interfaceIndex,
        out IPAddress address,
        out IPAddress networkMask,
        out IPAddress broadcastAddress,
        [NotNullWhen(true)] out string? interfaceName)
    {
        address = networkMask = broadcastAddress = IPAddress.Any;
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

        broadcastAddress = new IPAddress(broadcastAddressBytes);
        return true;
    }

    private void QueueDhcpProcessing()
    {
        throw new NotImplementedException();
    }
}