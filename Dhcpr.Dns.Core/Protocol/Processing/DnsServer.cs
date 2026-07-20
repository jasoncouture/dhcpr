using System.Buffers;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

using Dhcpr.Core;
using Dhcpr.Core.Queue;
using Dhcpr.Dns.Core.Protocol.Parser;

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed class DnsServer : BackgroundService
{
    private static readonly IPEndPoint AnyEndPoint = new(IPAddress.Any, 0);
    private readonly IMessageQueue<DnsPacketReceivedMessage> _messageQueue;
    private readonly IOptionsMonitor<DnsConfiguration> _options;
    private readonly ILogger<DnsServer> _logger;

    public DnsServer(
        IMessageQueue<DnsPacketReceivedMessage> messageQueue,
        IOptionsMonitor<DnsConfiguration> options,
        ILogger<DnsServer> logger)
    {
        _messageQueue = messageQueue;
        _options = options;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var listenEndPoints = _options.CurrentValue.GetListenEndpoints();
        if (listenEndPoints.Length == 0)
            throw new InvalidOperationException("DNS ListenAddresses must contain at least one listen URI.");

        try
        {
            var tasks = new List<Task>();
            foreach (var listen in listenEndPoints)
            {
                var addresses = await ResolveListenAddressesAsync(listen, stoppingToken);
                if (addresses.Length == 0)
                {
                    var target = listen.IsNetworkInterface
                        ? $"interface \"{listen.Host}\""
                        : $"host \"{listen.Host}\"";
                    var available = listen.IsNetworkInterface
                        ? $" Available interfaces: {string.Join(", ", DnsExtensions.GetNetworkInterfaceNames())}."
                        : string.Empty;
                    throw new InvalidOperationException(
                        $"DNS listen {target} did not resolve to any addresses.{available}");
                }

                foreach (var address in addresses)
                {
                    var endPoint = new IPEndPoint(address, listen.Port);
                    foreach (var protocol in ExpandProtocols(listen.Protocol))
                    {
                        tasks.Add(protocol switch
                        {
                            DnsListenProtocol.Udp => ServeUdpDnsAsync(endPoint, stoppingToken),
                            DnsListenProtocol.Tcp => ServeTcpDnsAsync(endPoint, stoppingToken),
                            _ => throw new InvalidOperationException($"Unsupported listen protocol: {protocol}")
                        });
                        _logger.LogInformation(
                            "DNS server listening on {Scheme}://{EndPoint}{Interface}",
                            protocol.ToString().ToLowerInvariant(),
                            endPoint,
                            listen.IsNetworkInterface ? $" (interface {listen.Host})" : string.Empty);
                    }
                }
            }

            await Task.WhenAll(tasks);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    private static IEnumerable<DnsListenProtocol> ExpandProtocols(DnsListenProtocol protocol)
        => protocol switch
        {
            DnsListenProtocol.Both => new[] { DnsListenProtocol.Udp, DnsListenProtocol.Tcp },
            DnsListenProtocol.Udp or DnsListenProtocol.Tcp => new[] { protocol },
            _ => throw new InvalidOperationException($"Unsupported listen protocol: {protocol}")
        };

    private static async Task<IPAddress[]> ResolveListenAddressesAsync(
        DnsListenEndpoint listen,
        CancellationToken cancellationToken)
    {
        if (listen.IsNetworkInterface)
            return DnsExtensions.GetNetworkInterfaceAddresses(listen.Host);

        if (IPAddress.TryParse(listen.Host, out var ipAddress))
            return new[] { ipAddress };

        return await System.Net.Dns.GetHostAddressesAsync(listen.Host, cancellationToken);
    }

    private async Task ServeUdpDnsAsync(IPEndPoint listenEndPoint, CancellationToken cancellationToken)
    {
        const int SioUdpConnreset = -1744830452;
        var udpClient = new UdpClient(listenEndPoint.AddressFamily);
        try
        {
            udpClient.ExclusiveAddressUse = false;
            udpClient.Client.SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ReuseAddress, true);
            if (listenEndPoint.AddressFamily == AddressFamily.InterNetwork)
            {
                udpClient.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.PacketInformation, true);
            }
            else if (listenEndPoint.AddressFamily == AddressFamily.InterNetworkV6)
            {
                udpClient.Client.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.PacketInformation, true);
            }

            // Prevents "connection forcibly closed" exceptions on ICMP port-unreachable.
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                udpClient.Client.IOControl((IOControlCode)SioUdpConnreset, new byte[] { 0, 0, 0, 0 }, null);

            udpClient.Client.Bind(listenEndPoint);
            var buffer = new byte[16384];
            while (!cancellationToken.IsCancellationRequested)
            {
                var result =
                    await udpClient.Client.ReceiveMessageFromAsync(buffer.AsMemory(), AnyEndPoint, cancellationToken);

                CreateContextAndQueueForProcessing(
                    result.RemoteEndPoint,
                    networkInterface: result.PacketInformation.Interface,
                    udpClient,
                    listenEndPoint,
                    buffer[..result.ReceivedBytes],
                    cancellationToken
                );
            }
        }
        finally
        {
            udpClient.Dispose();
        }
    }

    private async Task HandleTcpClient(TcpClient client, CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(16384);
        var bufferSegment = new ArraySegment<byte>(buffer, 0, 2);
        int length = -1;
        var cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        try
        {
            while (client.Connected && !cancellationTokenSource.IsCancellationRequested)
            {
                // To prevent DOS attacks, limit how long the connection can idle to a very short period of time.
                cancellationTokenSource.CancelAfter(TimeSpan.FromSeconds(10));
                var receivedLength = await client.Client.ReceiveAsync(bufferSegment, cancellationToken);
                if (!cancellationTokenSource.TryReset())
                {
                    cancellationTokenSource.Dispose();
                    cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                }

                // ReSharper disable once ConvertIfStatementToSwitchStatement
                if (receivedLength < 0) return;
                if (receivedLength == 0) continue;
                var nextSegment = new ArraySegment<byte>(buffer, bufferSegment.Offset + receivedLength,
                    bufferSegment.Count - receivedLength);
                if (length < 0)
                {
                    // Grab the first 2 bytes to get the message length.
                    length = BitConverter.ToUInt16(buffer).ToHostByteOrder();
                    if (length > 16384)
                    {
                        return;
                    }

                    bufferSegment = new ArraySegment<byte>(buffer, 0, length);
                    continue;
                }

                if (bufferSegment.Count + bufferSegment.Offset < length)
                {
                    // Need more data.
                    bufferSegment = nextSegment;
                    continue;
                }

                CreateContextAndQueueForProcessing(client, buffer.AsSpan(0, length).ToArray(), cancellationToken);
                // We sized our buffer so that we only asked for the exact amount we needed.
                // So we can just reset the buffer here without any risk of losing data.
                bufferSegment = new ArraySegment<byte>(buffer, 0, 2);
                length = -1;
            }
        }
        catch
        {
            // Ignored.
        }
        finally
        {
            cancellationTokenSource.Dispose();
            ArrayPool<byte>.Shared.Return(buffer);
            client.Dispose();
        }
    }

    private void CreateContextAndQueueForProcessing(
        TcpClient tcpClient,
        byte[] buffer,
        CancellationToken cancellationToken
    )
    {
        if (tcpClient.Client.RemoteEndPoint is not IPEndPoint remoteIPEndPoint ||
            tcpClient.Client.LocalEndPoint is not IPEndPoint localEndPoint)
        {
            return;
        }
        // We don't catch exceptions here like we do with UDP
        // because we want to disconnect the client if they send something that doesn't work.

        var message = DomainMessageEncoder.Decode(buffer);
        var context = new DomainMessageContext(remoteIPEndPoint, localEndPoint, message);

        var messageToQueue = new TcpDnsPacketReceivedMessage(context, tcpClient);
        _messageQueue.Enqueue(messageToQueue, cancellationToken);
    }

    private void CreateContextAndQueueForProcessing(
        EndPoint remoteEndPoint,
        int networkInterface,
        UdpClient udpClient,
        IPEndPoint listenEndPoint,
        byte[] bytes,
        CancellationToken cancellationToken
    )
    {
        if (remoteEndPoint is not IPEndPoint remoteIPEndPoint)
            return;
        try
        {
            var message = DomainMessageEncoder.Decode(bytes);
            var localAddress = GetLocalIPAddress(networkInterface, remoteIPEndPoint.AddressFamily);
            if (localAddress.Equals(IPAddress.Any) || localAddress.Equals(IPAddress.IPv6Any))
                localAddress = listenEndPoint.Address;

            var endPoint = new IPEndPoint(localAddress, listenEndPoint.Port);
            var context = new DomainMessageContext(remoteIPEndPoint, endPoint, message);

            var messageToQueue = new UdpDnsPacketReceivedMessage(context, udpClient);
            _messageQueue.Enqueue(messageToQueue, cancellationToken);
        }
        catch
        {
            // Ignored.
        }
    }

    private static IPAddress GetLocalIPAddress(int networkInterface, AddressFamily addressFamily)
    {
        if (addressFamily is not AddressFamily.InterNetwork and not AddressFamily.InterNetworkV6)
            throw new ArgumentException("Only IPv4 and IPv6 are supported.", nameof(addressFamily));
        foreach (var ipProperties in NetworkInterface.GetAllNetworkInterfaces().Select(i => i.GetIPProperties()))
        {
            if (ipProperties.UnicastAddresses.All(i => i.Address.AddressFamily != addressFamily))
                continue;
            if (addressFamily == AddressFamily.InterNetwork)
            {
                if (ipProperties.GetIPv4Properties().Index != networkInterface)
                    continue;

                return ipProperties.UnicastAddresses.First(i => i.Address.AddressFamily == addressFamily).Address;
            }

            if (ipProperties.GetIPv6Properties().Index != networkInterface)
                continue;
            return ipProperties.UnicastAddresses.First(i => i.Address.AddressFamily == addressFamily).Address;
        }

        return addressFamily == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any;
    }

    private static async Task<TcpClient?> AcceptNextConnectionAsync(TcpListener listener,
        CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested) return null;
        return await listener.AcceptTcpClientAsync(cancellationToken).AsTask().OperationCancelledToNull();
    }

    private async Task ServeTcpDnsAsync(IPEndPoint listenEndPoint, CancellationToken stoppingToken)
    {
        var tcpServer = new TcpListener(listenEndPoint);
        var activeTasks = new List<Task>();
        var acceptTask = AcceptNextConnectionAsync(tcpServer, stoppingToken);
        try
        {
            tcpServer.Start(ushort.MaxValue);
            while (!stoppingToken.IsCancellationRequested)
            {
                var completedTask = await Task.WhenAny(activeTasks.Append(acceptTask));
                await completedTask;
                activeTasks.Remove(completedTask);
                if (completedTask == acceptTask)
                {
                    var client = await acceptTask;
                    if (client is not null)
                        activeTasks.Add(HandleTcpClient(client, stoppingToken));
                    if (stoppingToken.IsCancellationRequested)
                        return;
                    acceptTask = AcceptNextConnectionAsync(tcpServer, stoppingToken);
                }
            }
        }
        finally
        {
            tcpServer.Stop();
            await Task.WhenAll(activeTasks.Append(acceptTask)).IgnoreExceptionsAsync();
        }
    }
}
