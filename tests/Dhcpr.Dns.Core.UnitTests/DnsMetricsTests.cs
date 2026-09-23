using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.UnitTests;

public class DnsMetricsTests
{
    [Fact]
    public void DurationSecondsBucketsResolveSubMillisecondHits()
    {
        Assert.Equal(0.000025, DnsMetrics.DurationSecondsBuckets[0]);
        Assert.Contains(0.001, DnsMetrics.DurationSecondsBuckets);
        Assert.True(DnsMetrics.DurationSecondsBuckets.Count(static b => b < 1) >= 6);
        Assert.DoesNotContain(5d, DnsMetrics.DurationSecondsBuckets[..3]);
    }
}
