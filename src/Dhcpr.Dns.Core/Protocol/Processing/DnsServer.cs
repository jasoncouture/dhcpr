using System.Buffers;
using System.Collections.Concurrent;
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
    private static readonly ConcurrentDictionary<(int Interface, AddressFamily Family), IPAddress> LocalAddressCache =
        new();

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

        // Shared token: if any listener dies, cancel the rest so the host fails closed.
        using var listenerCts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        var listenerToken = listenerCts.Token;

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
                            DnsListenProtocol.Udp => ServeUdpDnsAsync(endPoint, listenerToken),
                            DnsListenProtocol.Tcp => ServeTcpDnsAsync(endPoint, listenerToken),
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

            var completed = await Task.WhenAny(tasks);
            if (stoppingToken.IsCancellationRequested)
            {
                listenerCts.Cancel();
                await Task.WhenAll(tasks).IgnoreExceptionsAsync();
                return;
            }

            // A listener exited while the host is still running — tear down everything.
            listenerCts.Cancel();
            await Task.WhenAll(tasks).IgnoreExceptionsAsync();
            await completed;
            throw new InvalidOperationException("DNS listener stopped unexpectedly.");
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
            // ReceiveMessageFrom requires a remote endpoint template matching the socket family.
            // Per-listener instance: the API may mutate this endpoint.
            EndPoint remoteEndPoint = listenEndPoint.AddressFamily == AddressFamily.InterNetworkV6
                ? new IPEndPoint(IPAddress.IPv6Any, 0)
                : new IPEndPoint(IPAddress.Any, 0);
            while (!cancellationToken.IsCancellationRequested)
            {
                var result =
                    await udpClient.Client.ReceiveMessageFromAsync(buffer.AsMemory(), remoteEndPoint, cancellationToken);

                CreateContextAndQueueForProcessing(
                    result.RemoteEndPoint,
                    networkInterface: result.PacketInformation.Interface,
                    udpClient,
                    listenEndPoint,
                    buffer.AsSpan(0, result.ReceivedBytes),
                    cancellationToken
                );
            }
        }
        finally
        {
            udpClient.Dispose();
        }
    }

    private async Task HandleTcpClientAsync(TcpClient client, CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(16384);
        var cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        try
        {
            while (client.Connected && !cancellationTokenSource.IsCancellationRequested)
            {
                // Idle timeout to limit how long a client can hold the connection open.
                cancellationTokenSource.CancelAfter(TimeSpan.FromSeconds(10));
                var token = cancellationTokenSource.Token;

                await ReadExactAsync(client.Client, buffer.AsMemory(0, 2), token);
                var length = BitConverter.ToUInt16(buffer.AsSpan(0, 2)).ToHostByteOrder();
                if (length == 0 || length > buffer.Length)
                    return;

                await ReadExactAsync(client.Client, buffer.AsMemory(0, length), token);
                CreateContextAndQueueForProcessing(client, buffer.AsSpan(0, length).ToArray(), cancellationToken);

                if (!cancellationTokenSource.TryReset())
                {
                    cancellationTokenSource.Dispose();
                    cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Host is shutting down.
        }
        catch
        {
            // Idle timeout, remote close, or malformed client — drop the connection.
        }
        finally
        {
            cancellationTokenSource.Dispose();
            ArrayPool<byte>.Shared.Return(buffer);
            client.Dispose();
        }
    }

    private static async Task ReadExactAsync(Socket socket, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var received = await socket.ReceiveAsync(buffer[offset..], cancellationToken);
            if (received == 0)
                throw new IOException("DNS TCP client closed the connection.");
            offset += received;
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

        var message = DomainMessageEncoder.Decode(buffer);
        var context = new DomainMessageContext(remoteIPEndPoint, localEndPoint, message)
        {
            DnssecScope = new DnssecScope(),
            WorkBudget = new QueryWorkBudget()
        };

        var messageToQueue = new TcpDnsPacketReceivedMessage(context, tcpClient);
        _messageQueue.Enqueue(messageToQueue, cancellationToken);
    }

    private void CreateContextAndQueueForProcessing(
        EndPoint remoteEndPoint,
        int networkInterface,
        UdpClient udpClient,
        IPEndPoint listenEndPoint,
        ReadOnlySpan<byte> bytes,
        CancellationToken cancellationToken
    )
    {
        if (remoteEndPoint is not IPEndPoint remoteIPEndPoint)
            return;
        try
        {
            var message = DomainMessageEncoder.Decode(bytes);
            var localAddress = ResolveLocalAddress(listenEndPoint, networkInterface, remoteIPEndPoint.AddressFamily);
            var endPoint = new IPEndPoint(localAddress, listenEndPoint.Port);
            var context = new DomainMessageContext(remoteIPEndPoint, endPoint, message)
            {
                DnssecScope = new DnssecScope(),
                WorkBudget = new QueryWorkBudget()
            };

            var messageToQueue = new UdpDnsPacketReceivedMessage(context, udpClient);
            _messageQueue.Enqueue(messageToQueue, cancellationToken);
        }
        catch
        {
            // Ignored.
        }
    }

    private static IPAddress ResolveLocalAddress(
        IPEndPoint listenEndPoint,
        int networkInterface,
        AddressFamily addressFamily)
    {
        // Specific listen address (e.g. 127.0.0.1) — never scan NICs on the hot path.
        if (!listenEndPoint.Address.Equals(IPAddress.Any) &&
            !listenEndPoint.Address.Equals(IPAddress.IPv6Any))
            return listenEndPoint.Address;

        var localAddress = GetLocalIPAddress(networkInterface, addressFamily);
        if (localAddress.Equals(IPAddress.Any) || localAddress.Equals(IPAddress.IPv6Any))
            return listenEndPoint.Address;
        return localAddress;
    }

    private static IPAddress GetLocalIPAddress(int networkInterface, AddressFamily addressFamily)
    {
        if (addressFamily is not AddressFamily.InterNetwork and not AddressFamily.InterNetworkV6)
            throw new ArgumentException("Only IPv4 and IPv6 are supported.", nameof(addressFamily));

        return LocalAddressCache.GetOrAdd((networkInterface, addressFamily), static key =>
        {
            foreach (var ipProperties in NetworkInterface.GetAllNetworkInterfaces().Select(i => i.GetIPProperties()))
            {
                if (ipProperties.UnicastAddresses.All(i => i.Address.AddressFamily != key.Family))
                    continue;
                if (key.Family == AddressFamily.InterNetwork)
                {
                    if (ipProperties.GetIPv4Properties().Index != key.Interface)
                        continue;

                    return ipProperties.UnicastAddresses.First(i => i.Address.AddressFamily == key.Family).Address;
                }

                if (ipProperties.GetIPv6Properties().Index != key.Interface)
                    continue;
                return ipProperties.UnicastAddresses.First(i => i.Address.AddressFamily == key.Family).Address;
            }

            return key.Family == AddressFamily.InterNetworkV6 ? IPAddress.IPv6Any : IPAddress.Any;
        });
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
        Task<TcpClient?>? acceptTask = null;
        try
        {
            // Must Start before Accept — AcceptTcpClientAsync throws if not listening.
            tcpServer.Start(ushort.MaxValue);
            acceptTask = AcceptNextConnectionAsync(tcpServer, stoppingToken);
            while (!stoppingToken.IsCancellationRequested)
            {
                var completedTask = await Task.WhenAny(activeTasks.Append(acceptTask));
                await completedTask;
                activeTasks.Remove(completedTask);
                if (completedTask == acceptTask)
                {
                    var client = await acceptTask;
                    if (client is not null)
                        activeTasks.Add(HandleTcpClientAsync(client, stoppingToken));
                    if (stoppingToken.IsCancellationRequested)
                        return;
                    acceptTask = AcceptNextConnectionAsync(tcpServer, stoppingToken);
                }
            }
        }
        finally
        {
            tcpServer.Stop();
            var pending = acceptTask is null ? activeTasks : activeTasks.Append(acceptTask);
            await Task.WhenAll(pending).IgnoreExceptionsAsync();
        }
    }
}
