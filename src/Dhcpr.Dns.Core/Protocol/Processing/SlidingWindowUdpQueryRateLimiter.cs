using System.Net;
using System.Net.Sockets;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// Sliding window for UDP keyed by client prefix <em>and</em> QNAME.
/// IPv4 uses the address; IPv6 uses /64. Idle keys expire.
/// Loopback is not limited (health checks).
/// </summary>
public sealed class SlidingWindowUdpQueryRateLimiter : IUdpQueryRateLimiter, IDisposable
{
    private readonly IOptionsMonitor<DnsConfiguration> _options;
    private readonly MemoryCache _cache = new(new MemoryCacheOptions
    {
        ExpirationScanFrequency = TimeSpan.FromSeconds(5)
    });

    public SlidingWindowUdpQueryRateLimiter(IOptionsMonitor<DnsConfiguration> options)
    {
        _options = options;
    }

    public UdpRateLimitAction Record(IPAddress? client, DomainLabels name)
    {
        var limit = _options.CurrentValue.UdpRateLimit;
        if (!limit.Enabled)
            return UdpRateLimitAction.Allow;

        if (client is null)
            return UdpRateLimitAction.Drop;

        if (IPAddress.IsLoopback(client))
            return UdpRateLimitAction.Allow;

        var key = $"{PartitionKey(client)}\0{name.ToString().ToLowerInvariant()}";
        var window = TimeSpan.FromMilliseconds(limit.WindowMilliseconds);
        var counter = _cache.GetOrCreate(key, entry =>
        {
            entry.SlidingExpiration = window + window;
            return new SlidingWindowCounter(window, limit.SegmentsPerWindow);
        });

        var count = counter!.Record();
        if (count <= limit.RefuseLimit)
            return UdpRateLimitAction.Allow;
        if (count <= limit.DropLimit)
            return UdpRateLimitAction.Refuse;
        return UdpRateLimitAction.Drop;
    }

    internal static string PartitionKey(IPAddress address)
    {
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();

        if (address.AddressFamily != AddressFamily.InterNetworkV6)
            return address.ToString();

        Span<byte> bytes = stackalloc byte[16];
        if (!address.TryWriteBytes(bytes, out _))
            return address.ToString();

        bytes[8..].Clear();
        return new IPAddress(bytes).ToString();
    }

    public void Dispose() => _cache.Dispose();
}
