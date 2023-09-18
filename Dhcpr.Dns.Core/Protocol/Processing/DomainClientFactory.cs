﻿using Dhcpr.Core.Linq;

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

    public async ValueTask<IDomainClient> GetParallelDomainClient(IEnumerable<DomainClientOptions> options,
        CancellationToken cancellationToken = default)
    {
        var clients = await Task.WhenAll(options.Select(i => GetDomainClient(i, cancellationToken).AsTask()));
        return new DomainClientParallelWrapper(clients);
    }

    public ValueTask<IDomainClient> GetDomainClient(DomainClientOptions options,
        CancellationToken cancellationToken = default)
    {
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
            clients.Add(new UdpDomainClient(_socketFactory.GetUdpClient(), options.EndPoint));
        }

        while (clients.Count > 2)
        {
            var wrappedClients = new DomainClientWrapper(clients[^1], clients[^2]);
            clients.RemoveAt(clients.Count - 1);
            clients[^1] = wrappedClients;
        }

        if (options.TimeOut > TimeSpan.Zero)
        {
            clients[0] = new DomainClientTimeoutWrapper(clients[0], options.TimeOut);
        }

        return ValueTask.FromResult(clients[0]);
    }
}