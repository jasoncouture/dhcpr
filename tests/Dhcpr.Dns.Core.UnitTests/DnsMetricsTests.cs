using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.UnitTests;

public class DnsMetricsTests
{
    [Fact]
    public void DurationSecondsBucketsStartInMillisecondsNotFiveSeconds()
    {
        Assert.Equal(0.001, DnsMetrics.DurationSecondsBuckets[0]);
        Assert.True(DnsMetrics.DurationSecondsBuckets.Count(static b => b < 1) >= 6);
        Assert.DoesNotContain(5d, DnsMetrics.DurationSecondsBuckets[..3]);
    }
}
