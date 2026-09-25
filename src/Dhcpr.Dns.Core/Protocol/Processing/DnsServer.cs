using System.Buffers;
using System.Collections.Concurrent;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

using Dhcpr.Core;
using Dhcpr.Dns.Core.Protocol.Parser;

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed partial class DnsServer : BackgroundService
{
    /// <summary>
    /// A client must finish the TLS handshake and deliver a complete
    /// length-prefixed DNS message within this interval or the TCP/DoT
    /// connection is closed.
    /// </summary>
    public static readonly TimeSpan TcpReadTimeout = TimeSpan.FromSeconds(1);

    /// <summary>
    /// Kernel accept-queue depth for classic TCP and DoT. Excess SYNs
    /// are dropped instead of parking completed handshakes in the kernel.
    /// </summary>
    public const int ListenBacklog = 20;

    private static readonly ConcurrentDictionary<(int Interface, AddressFamily Family), IPAddress> _localAddressCache =
        new();

    private readonly IDnsQueryPipeline _pipeline;
    private readonly IOptionsMonitor<DnsConfiguration> _options;
    private readonly IOptionsMonitor<TlsConfiguration> _tlsOptions;
    private readonly ITlsServerCertificateProvider _certificates;
    private readonly ILogger<DnsServer> _logger;
    private readonly IDnsListenerReadiness? _readiness;

    public DnsServer(
        IDnsQueryPipeline pipeline,
        IOptionsMonitor<DnsConfiguration> options,
        IOptionsMonitor<TlsConfiguration> tlsOptions,
        ITlsServerCertificateProvider certificates,
        ILogger<DnsServer> logger,
        IDnsListenerReadiness? readiness = null)
    {
        _pipeline = pipeline;
        _options = options;
        _tlsOptions = tlsOptions;
        _certificates = certificates;
        _logger = logger;
        _readiness = readiness;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var listenEndPoints = _options.CurrentValue.GetListenEndpoints();
        if (listenEndPoints.Length == 0)
            throw new InvalidOperationException("DNS ListenAddresses must contain at least one listen URI.");

        // Shared token: if any listener dies, cancel the rest so the host fails closed.
        using var listenerTokenSource = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        var listenerToken = listenerTokenSource.Token;

        try
        {
            var planned = new List<(string Name, Func<CancellationToken, Task> Run)>();
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

                var interfaceSuffix = listen.IsNetworkInterface ? $" (interface {listen.Host})" : string.Empty;
                foreach (var address in addresses)
                {
                    var endPoint = new IPEndPoint(address, listen.Port);
                    foreach (var protocol in ExpandProtocols(listen.Protocol))
                    {
                        var name = $"{protocol.ToString().ToLowerInvariant()}://{endPoint}";
                        planned.Add((name, protocol switch
                        {
                            DnsListenProtocol.Udp => ct => ServeUdpDnsAsync(endPoint, name, interfaceSuffix, ct),
                            DnsListenProtocol.Tcp => ct => ServeTcpDnsAsync(endPoint, name, interfaceSuffix, ct),
                            _ => throw new InvalidOperationException($"Unsupported listen protocol: {protocol}")
                        }));
                    }
                }
            }

            var tls = _tlsOptions.CurrentValue;
            if (tls.Enabled)
            {
                if (!tls.TryValidate(out var tlsError))
                    throw new InvalidOperationException(tlsError);
                await _certificates.Ready.WaitAsync(stoppingToken).ConfigureAwait(false);
                _ = _certificates.GetServerCertificateContext();

                foreach (var listener in tls.GetParsedListeners())
                {
                    var addresses = await ResolveEndPointAddressesAsync(listener, stoppingToken);
                    if (addresses.Length == 0)
                    {
                        throw new InvalidOperationException(
                            $"TLS listen \"{listener}\" did not resolve to any addresses.");
                    }

                    var port = GetListenPort(listener);
                    foreach (var address in addresses)
                    {
                        var endPoint = new IPEndPoint(address, port);
                        var name = $"tls://{endPoint}";
                        planned.Add((name, ct => ServeTlsDnsAsync(endPoint, name, ct)));
                    }
                }
            }

            _readiness?.SetExpected(planned.ConvertAll(listener => listener.Name));
            var tasks = planned.ConvertAll(listener => listener.Run(listenerToken));
            var completed = await Task.WhenAny(tasks);
            if (stoppingToken.IsCancellationRequested)
            {
                await listenerTokenSource.CancelAsync();
                // ReSharper disable once MethodSupportsCancellation
#pragma warning disable CA2016
                await Task.WhenAll(tasks).IgnoreExceptionsAsync();
#pragma warning restore CA2016
                return;
            }

            // A listener exited while the host is still running — tear down everything.
            await listenerTokenSource.CancelAsync();
            // ReSharper disable once MethodSupportsCancellation
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

    private static async Task<IPAddress[]> ResolveEndPointAddressesAsync(
        EndPoint listener,
        CancellationToken cancellationToken)
    {
        switch (listener)
        {
            case IPEndPoint ip:
                return [ip.Address];
            case DnsEndPoint dns:
                return await System.Net.Dns.GetHostAddressesAsync(dns.Host, cancellationToken);
            default:
                throw new InvalidOperationException($"Unsupported TLS listen endpoint: {listener}");
        }
    }

    private static int GetListenPort(EndPoint listener)
        => listener switch
        {
            IPEndPoint ip => ip.Port,
            DnsEndPoint dns => dns.Port,
            _ => throw new InvalidOperationException($"Unsupported TLS listen endpoint: {listener}")
        };

    private async Task ServeUdpDnsAsync(
        IPEndPoint listenEndPoint,
        string listenerName,
        string interfaceSuffix,
        CancellationToken cancellationToken)
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
            _readiness?.MarkBound(listenerName);
            LogListening(_logger, "udp", listenEndPoint, interfaceSuffix);
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

                CreateContextAndProcessUdp(
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

    // ReSharper disable once AsyncVoidMethod
    public async void HandleTcpClientAsync(TcpClient client, CancellationToken cancellationToken)
    {
        try
        {
            await HandleStreamClientAsync(client, client.GetStream(), DnsQuerySource.Tcp, cancellationToken);
        }
        catch (Exception exception)
        {
            LogTcpClientFailed(_logger, exception, TryRemoteEndPoint(client));
            client.Dispose();
        }
    }

    // ReSharper disable once AsyncVoidMethod
    public async void HandleTlsClientAsync(TcpClient client, CancellationToken cancellationToken)
    {
        // AuthenticateAsServerAsync runs DoSslHandshake on this thread and
        // does not return a Task until that call yields. WaitAsync is applied
        // to that Task, so it never arms while the handshake is stuck, and
        // the accept loop never gets back to accept. TCP's first read returns
        // a Task immediately. Close the socket from a timer started first.
        var remoteEndPoint = TryRemoteEndPoint(client);
        await Task.Yield();
        SslStream? sslStream = null;
        var abort = new HandshakeAbort(client);
        using var abortHandshake = new Timer(
            static state => ((HandshakeAbort)state!).TryClose(),
            abort,
            TcpReadTimeout,
            Timeout.InfiniteTimeSpan);
        try
        {
            sslStream = new SslStream(client.GetStream(), leaveInnerStreamOpen: false);
            await sslStream.AuthenticateAsServerAsync(CreateTlsServerOptions(), cancellationToken);
            abort.Finish();
            await HandleStreamClientAsync(client, sslStream, DnsQuerySource.Dot, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception) when (abort.Closed)
        {
            LogDotHandshakeTimedOut(_logger, remoteEndPoint);
        }
        catch (Exception exception)
        {
            LogDotClientFailed(_logger, exception, remoteEndPoint);
        }
        finally
        {
            if (sslStream is not null)
                await sslStream.DisposeAsync();
            client.Dispose();
        }
    }

    private sealed class HandshakeAbort(TcpClient client)
    {
        private int _state;

        public bool Closed => Volatile.Read(ref _state) == ClosedState;

        public void Finish() => Interlocked.CompareExchange(ref _state, FinishedState, 0);

        public void TryClose()
        {
            if (Interlocked.CompareExchange(ref _state, ClosedState, 0) != 0)
                return;

            try
            {
                client.Client.Close();
            }
            catch (ObjectDisposedException)
            {
            }
        }

        private const int FinishedState = 1;
        private const int ClosedState = 2;
    }

    private SslServerAuthenticationOptions CreateTlsServerOptions()
        => new()
        {
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            ClientCertificateRequired = false,
            ApplicationProtocols = [new SslApplicationProtocol("dot")],
            ServerCertificateContext = _certificates.GetServerCertificateContext()
        };

    internal async Task HandleStreamClientAsync(
        TcpClient client,
        Stream stream,
        DnsQuerySource source,
        CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(16384);
        var cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        try
        {
            while (client.Connected && !cancellationToken.IsCancellationRequested)
            {
                // Incomplete message only. A query already in flight must not
                // share this deadline — resolution can outlive an idle read.
                cancellationTokenSource.CancelAfter(TcpReadTimeout);
                var idleCancellationToken = cancellationTokenSource.Token;

                await ReadExactAsync(stream, buffer.AsMemory(0, 2), idleCancellationToken);
                var length = BitConverter.ToUInt16(buffer.AsSpan(0, 2)).ToHostByteOrder();
                if (length == 0 || length > buffer.Length)
                    return;

                await ReadExactAsync(stream, buffer.AsMemory(0, length), idleCancellationToken);
                if (!cancellationTokenSource.TryReset())
                {
                    cancellationTokenSource.Dispose();
                    cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                }

                var reply = CreateContextAndProcessTcp(
                    client,
                    stream,
                    buffer.AsSpan(0, length).ToArray(),
                    source,
                    cancellationToken);
                if (reply is not null)
                    await reply.ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            // Host is shutting down.
        }
        catch (OperationCanceledException exception)
        {
            LogStreamClientDropped(_logger, exception, source, TryRemoteEndPoint(client));
        }
        catch (Exception exception)
        {
            LogStreamClientFailed(_logger, exception, source, TryRemoteEndPoint(client));
        }
        finally
        {
            cancellationTokenSource.Dispose();
            ArrayPool<byte>.Shared.Return(buffer);
            client.Dispose();
        }
    }

    private static async Task ReadExactAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        var offset = 0;
        while (offset < buffer.Length)
        {
            var received = await stream.ReadAsync(buffer[offset..], cancellationToken);
            if (received == 0)
                throw new IOException("DNS TCP client closed the connection.");
            offset += received;
        }
    }

    private Task? CreateContextAndProcessTcp(
        TcpClient tcpClient,
        Stream stream,
        byte[] buffer,
        DnsQuerySource source,
        CancellationToken cancellationToken
    )
    {
        if (tcpClient.Client.RemoteEndPoint is not IPEndPoint remoteIPEndPoint ||
            tcpClient.Client.LocalEndPoint is not IPEndPoint localEndPoint)
        {
            return null;
        }

        var message = DomainMessageEncoder.Decode(buffer);
        var context = new DomainMessageContext(remoteIPEndPoint, localEndPoint, message)
        {
            DnssecScope = new DnssecScope(),
            WorkBudget = new QueryWorkBudget(),
            NameserverTips = new NameserverTipCache(),
            QueryCoalescer = new QueryCoalescer(),
            ParentTraceContext = DnsInstrumentation.CaptureContext(),
            Source = source
        };

        return ProcessAndSendTcpAsync(context, stream, cancellationToken);
    }

    private void CreateContextAndProcessUdp(
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
                WorkBudget = new QueryWorkBudget(),
                NameserverTips = new NameserverTipCache(),
                QueryCoalescer = new QueryCoalescer(),
                ParentTraceContext = DnsInstrumentation.CaptureContext(),
                Source = DnsQuerySource.Udp
            };

            ProcessAndSendUdp(context, udpClient, remoteIPEndPoint, cancellationToken);
        }
        catch (Exception exception)
        {
            LogUdpDecodeFailed(_logger, exception, remoteEndPoint);
        }
    }

    private async void ProcessAndSendUdp(
        DomainMessageContext context,
        UdpClient udpClient,
        IPEndPoint clientEndPoint,
        CancellationToken cancellationToken)
    {
        await Task.Yield();
        try
        {
            var response = await _pipeline.ExecuteAsync(context, cancellationToken).ConfigureAwait(false);
            if (response is null)
                return;

            await DomainMessageContextMessageProcessor.WriteUdpAsync(
                    udpClient,
                    clientEndPoint,
                    response,
                    _logger,
                    cancellationToken)
                .ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
        catch (Exception exception)
        {
            LogUdpProcessFault(_logger, exception);
        }
    }

    private async Task ProcessAndSendTcpAsync(
        DomainMessageContext context,
        Stream stream,
        CancellationToken cancellationToken)
    {
        var response = await _pipeline.ExecuteAsync(context, cancellationToken).ConfigureAwait(false);
        if (response is null)
            return;

        await DomainMessageContextMessageProcessor.WriteTcpAsync(stream, response, cancellationToken)
            .ConfigureAwait(false);
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

        return _localAddressCache.GetOrAdd((networkInterface, addressFamily), static key =>
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
        var client = await listener.AcceptTcpClientAsync(cancellationToken).AsTask().OperationCancelledToNull();
        if (client is not null)
            client.NoDelay = true;
        return client;
    }

    private async Task ServeTcpDnsAsync(
        IPEndPoint listenEndPoint,
        string listenerName,
        string interfaceSuffix,
        CancellationToken stoppingToken)
    {
        var tcpServer = new TcpListener(listenEndPoint);
        try
        {
            // Must Start before Accept — AcceptTcpClientAsync throws if not listening.
            tcpServer.Start(ListenBacklog);
            _readiness?.MarkBound(listenerName);
            LogListening(_logger, "tcp", listenEndPoint, interfaceSuffix);
            while (!stoppingToken.IsCancellationRequested)
            {
                var client = await AcceptNextConnectionAsync(tcpServer, stoppingToken);
                if (client is null)
                    return;
                HandleTcpClientAsync(client, stoppingToken);
            }
        }
        finally
        {
            tcpServer.Stop();
        }
    }

    private async Task ServeTlsDnsAsync(
        IPEndPoint listenEndPoint,
        string listenerName,
        CancellationToken stoppingToken)
    {
        var tcpServer = new TcpListener(listenEndPoint);
        try
        {
            tcpServer.Start(ListenBacklog);
            _readiness?.MarkBound(listenerName);
            LogListening(_logger, "tls", listenEndPoint, string.Empty);
            while (!stoppingToken.IsCancellationRequested)
            {
                var client = await AcceptNextConnectionAsync(tcpServer, stoppingToken);
                if (client is null)
                    return;
                HandleTlsClientAsync(client, stoppingToken);
            }
        }
        finally
        {
            tcpServer.Stop();
        }
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "DNS server listening on {Scheme}://{EndPoint}{Interface}")]
    private static partial void LogListening(ILogger logger, string scheme, IPEndPoint endPoint, string @interface);

    [LoggerMessage(Level = LogLevel.Error, Message = "UDP DNS process-and-send failed")]
    private static partial void LogUdpProcessFault(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Debug, Message = "UDP DNS datagram from {RemoteEndPoint} dropped")]
    private static partial void LogUdpDecodeFailed(ILogger logger, Exception exception, EndPoint remoteEndPoint);

    [LoggerMessage(Level = LogLevel.Error, Message = "TCP DNS client {RemoteEndPoint} failed")]
    private static partial void LogTcpClientFailed(ILogger logger, Exception exception, EndPoint? remoteEndPoint);

    [LoggerMessage(Level = LogLevel.Error, Message = "DoT client {RemoteEndPoint} failed")]
    private static partial void LogDotClientFailed(ILogger logger, Exception exception, EndPoint? remoteEndPoint);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DoT client {RemoteEndPoint} handshake timed out")]
    private static partial void LogDotHandshakeTimedOut(ILogger logger, EndPoint? remoteEndPoint);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNS {Source} client {RemoteEndPoint} idle read timed out")]
    private static partial void LogStreamClientDropped(ILogger logger, Exception exception, DnsQuerySource source, EndPoint? remoteEndPoint);

    [LoggerMessage(Level = LogLevel.Warning, Message = "DNS {Source} client {RemoteEndPoint} dropped")]
    private static partial void LogStreamClientFailed(ILogger logger, Exception exception, DnsQuerySource source, EndPoint? remoteEndPoint);

    private static EndPoint? TryRemoteEndPoint(TcpClient client)
    {
        try
        {
            return client.Client.RemoteEndPoint;
        }
        catch (ObjectDisposedException)
        {
            return null;
        }
    }
}
