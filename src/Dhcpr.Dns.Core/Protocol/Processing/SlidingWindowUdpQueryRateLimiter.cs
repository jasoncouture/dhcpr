using System.Net;
using System.Net.Sockets;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// Two sliding windows for UDP: client+QNAME+QTYPE, and client IP alone at
/// <see cref="IpLimitMultiplier"/> times those thresholds. IPv6 is /64.
/// Idle keys expire. Loopback is not limited (health checks).
/// </summary>
public sealed class SlidingWindowUdpQueryRateLimiter : IUdpQueryRateLimiter, IDisposable
{
    public const int IpLimitMultiplier = 5;

    private readonly IOptionsMonitor<DnsConfiguration> _options;
    private readonly MemoryCache _cache = new(new MemoryCacheOptions
    {
        ExpirationScanFrequency = TimeSpan.FromSeconds(5)
    });

    public SlidingWindowUdpQueryRateLimiter(IOptionsMonitor<DnsConfiguration> options)
    {
        _options = options;
    }

    public UdpRateLimitAction Record(IPAddress? client, DomainLabels name, DomainRecordType type)
    {
        var limit = _options.CurrentValue.UdpRateLimit;
        if (!limit.Enabled)
            return UdpRateLimitAction.Allow;

        if (client is null)
            return UdpRateLimitAction.Drop;

        if (IPAddress.IsLoopback(client))
            return UdpRateLimitAction.Allow;

        var prefix = PartitionKey(client);
        var window = TimeSpan.FromMilliseconds(limit.WindowMilliseconds);
        var questionCount = Counter($"{prefix}\0{name.ToString().ToLowerInvariant()}\0{(ushort)type}", window, limit)
            .Record();
        var ipCount = Counter(prefix, window, limit).Record();

        var question = Classify(questionCount, limit.RefuseLimit, limit.DropLimit);
        var ip = Classify(
            ipCount,
            limit.RefuseLimit * IpLimitMultiplier,
            limit.DropLimit * IpLimitMultiplier);
        return question > ip ? question : ip;
    }

    private SlidingWindowCounter Counter(string key, TimeSpan window, UdpRateLimitConfiguration limit)
        => _cache.GetOrCreate(key, entry =>
        {
            entry.SlidingExpiration = window + window;
            return new SlidingWindowCounter(window, limit.SegmentsPerWindow);
        })!;

    private static UdpRateLimitAction Classify(int count, int refuseLimit, int dropLimit)
    {
        if (count <= refuseLimit)
            return UdpRateLimitAction.Allow;
        if (count <= dropLimit)
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
