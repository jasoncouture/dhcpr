using System.Diagnostics.CodeAnalysis;

using Dhcpr.Core;

namespace Dhcpr.Dns.Core;

/// <summary>
/// Two-tier sliding-window UDP rate limit under <c>DNS:UdpRateLimit</c>.
/// TCP, DoT, and DoH are not limited.
/// </summary>
public sealed class UdpRateLimitConfiguration : IValidateSelf
{
    public bool Enabled { get; set; } = true;

    /// <summary>Queries per partition that still get a real answer.</summary>
    public int RefuseLimit { get; set; } = 20;

    /// <summary>
    /// Queries per partition that still get <c>REFUSED</c>. Above this, no reply.
    /// </summary>
    public int DropLimit { get; set; } = 40;

    /// <summary>Sliding window length.</summary>
    public int WindowMilliseconds { get; set; } = 1000;

    /// <summary>
    /// How many buckets the window is split into. More segments = smoother
    /// sliding (10 × 100 ms for a 1 s window).
    /// </summary>
    public int SegmentsPerWindow { get; set; } = 10;

    public bool Validate() => TryValidate(out _);

    public bool TryValidate([NotNullWhen(false)] out string? error)
    {
        if (RefuseLimit < 1)
        {
            error = "DNS:UdpRateLimit:RefuseLimit must be at least 1";
            return false;
        }

        if (DropLimit <= RefuseLimit)
        {
            error = "DNS:UdpRateLimit:DropLimit must be greater than RefuseLimit";
            return false;
        }

        if (RefuseLimit > int.MaxValue / 5 || DropLimit > int.MaxValue / 5)
        {
            error = "DNS:UdpRateLimit refuse/drop limits are too large for the IP-wide 5x window";
            return false;
        }

        if (WindowMilliseconds is < 100 or > 60_000)
        {
            error = "DNS:UdpRateLimit:WindowMilliseconds must be between 100 and 60000";
            return false;
        }

        if (SegmentsPerWindow is < 2 or > 100)
        {
            error = "DNS:UdpRateLimit:SegmentsPerWindow must be between 2 and 100";
            return false;
        }

        error = null;
        return true;
    }
}
