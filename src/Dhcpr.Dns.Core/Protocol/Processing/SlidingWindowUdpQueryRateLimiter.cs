using System.Net;
using System.Net.Sockets;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// Two sliding windows for UDP: client+QNAME+QTYPE (soft REFUSED then drop),
/// and client IP over a window <see cref="IpLimitMultiplier"/> times as long.
/// At or above the per-question rate on that longer window is abuse: no reply.
/// IPv6 is /64. Idle keys expire. Loopback is not limited.
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
        var questionCount = Counter(
                $"{prefix}\0{name.ToString().ToLowerInvariant()}\0{(ushort)type}",
                window,
                limit.SegmentsPerWindow)
            .Record();
        var ipCount = Counter(
                prefix,
                window * IpLimitMultiplier,
                limit.SegmentsPerWindow * IpLimitMultiplier)
            .Record();

        var question = Classify(questionCount, limit.RefuseLimit, limit.DropLimit);
        // Same rate as RefuseLimit, measured over the longer window (20/s × 5s = 100).
        // At or above that rate is abuse: drop, no REFUSED band.
        var ipBudget = limit.RefuseLimit * IpLimitMultiplier;
        var ip = ipCount < ipBudget ? UdpRateLimitAction.Allow : UdpRateLimitAction.Drop;
        return question > ip ? question : ip;
    }

    private SlidingWindowCounter Counter(string key, TimeSpan window, int segmentsPerWindow)
        => _cache.GetOrCreate(key, entry =>
        {
            entry.SlidingExpiration = window + window;
            return new SlidingWindowCounter(window, segmentsPerWindow);
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
