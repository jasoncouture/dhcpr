using System.Net;
using System.Net.Sockets;

using Dhcpr.Core.Linq;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed class DomainClientFactory : IDomainClientFactory
{
    private readonly ISocketFactory _socketFactory;
    private readonly IInternalDomainClient _internalDomainClient;

    public DomainClientFactory(ISocketFactory socketFactory, IInternalDomainClient internalDomainClient)
    {
        _socketFactory = socketFactory;
        _internalDomainClient = internalDomainClient;
    }

    public async ValueTask<IDomainClient> GetParallelDomainClientAsync(IEnumerable<DomainClientOptions> options,
        CancellationToken cancellationToken)
    {
        var clients = await Task.WhenAll(options.Select(i => GetDomainClientAsync(i, cancellationToken).AsTask()));
        return new DomainClientParallelWrapper(clients);
    }

    public ValueTask<IDomainClient> GetDomainClientAsync(DomainClientOptions options,
        CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        if (options.Type != DomainClientType.Internal &&
            ReferenceEquals(options.EndPoint, DomainClientOptions.DefaultEndPoint))
        {
            throw new ArgumentException("TCP and UDP clients require an IP End point", nameof(options));
        }

        using var clients = ListPool<IDomainClient>.Default.Get();

        if (options.Type.HasFlag(DomainClientType.Internal))
        {
            clients.Add(_internalDomainClient);
        }

        if (options.Type.HasFlag(DomainClientType.Udp))
        {
            var localEndPoint = options.EndPoint switch
            {
                { AddressFamily: AddressFamily.InterNetwork } => new IPEndPoint(IPAddress.Any, 0),
                { AddressFamily: AddressFamily.InterNetworkV6 } => new IPEndPoint(IPAddress.IPv6Any, 0),
                _ => throw new InvalidOperationException(
                    $"Unsupported endpoint address family {options.EndPoint.AddressFamily}")
            };
            var udpClient = new UdpDomainClient(_socketFactory.GetUdpClient(localEndPoint), options.EndPoint);
            var tcpClient = new TcpDomainClient(_socketFactory, options.EndPoint);
            clients.Add(new DomainClientTruncationFallbackWrapper(udpClient, tcpClient));
        }
        else if (options.Type.HasFlag(DomainClientType.Tcp))
        {
            clients.Add(new TcpDomainClient(_socketFactory, options.EndPoint));
        }

        while (clients.Count > 2)
        {
            var wrappedClients = new DomainClientWrapper(clients[^1], clients[^2]);
            clients.RemoveAt(clients.Count - 1);
            clients[^1] = wrappedClients;
        }

        if (clients.Count == 0)
            throw new ArgumentException("No DNS client types requested", nameof(options));

        // Internal resolution walks the full middleware/resolver chain; do not apply the
        // short UDP network timeout (default 250ms) or CNAME/NS-glue chases will fail.
        var applyTimeout = options.TimeOut > TimeSpan.Zero &&
                           !options.Type.HasFlag(DomainClientType.Internal);
        if (applyTimeout)
        {
            clients[0] = new DomainClientTimeoutWrapper(clients[0], options.TimeOut);
        }

        return ValueTask.FromResult(clients[0]);
    }
}
