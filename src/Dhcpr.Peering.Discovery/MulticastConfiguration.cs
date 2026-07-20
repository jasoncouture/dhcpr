using System.Net;

using Dhcpr.Core;

namespace Dhcpr.Peering.Discovery;

public sealed class MulticastConfiguration
{
    private const int DefaultPort = 5353;
    public string Address { get; set; } = $"224.0.0.53:{DefaultPort}";


    public bool Validate()
    {
        return Address.IsValidMulticastAddress(); ;
    }

    private IPEndPoint? _cachedEndpoint;
    internal void ClearCachedEndpoint() => _cachedEndpoint = null;

    public IPEndPoint GetMulticastEndpoint()
    {
        var cached = _cachedEndpoint;
        if (cached is not null) return cached;
        if (!Validate())
            throw new InvalidOperationException("Configuration is not valid.");
        if (IPEndPoint.TryParse(Address, out var endpoint))
            return _cachedEndpoint = endpoint;

        var address = IPAddress.Parse(Address);

        return _cachedEndpoint = new IPEndPoint(address, DefaultPort);
    }
}