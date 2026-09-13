using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.UnitTests;

public class SlidingWindowCounterTests
{
    [Fact]
    public void CountsWithinWindowThenSlidesOff()
    {
        // 10 segments × 100 ticks = 1000-tick window.
        var counter = new SlidingWindowCounter(segmentsPerWindow: 10, segmentTicks: 100);

        Assert.Equal(1, counter.Record(0));
        Assert.Equal(2, counter.Record(0));
        Assert.Equal(3, counter.Record(50));

        // Segment 0 is outside [1, 10].
        Assert.Equal(1, counter.Record(1000));
    }

    [Fact]
    public void OldestSegmentDropsAsWindowAdvances()
    {
        var counter = new SlidingWindowCounter(segmentsPerWindow: 10, segmentTicks: 100);

        for (var i = 0; i < 5; i++)
            counter.Record(0);

        Assert.Equal(6, counter.Record(200));
        // t=0 (5) has aged out; t=200 (1) remains plus this event.
        Assert.Equal(2, counter.Record(1000));
    }
}
