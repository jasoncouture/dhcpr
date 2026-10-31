using System.Diagnostics;

namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// Segmented sliding window: counts live in a ring keyed by absolute segment
/// id. The sum is over the last <c>segments</c> buckets, so the limit tracks
/// the trailing window instead of a fixed clock boundary.
/// </summary>
public sealed class SlidingWindowCounter
{
    private readonly int _segmentCount;
    private readonly long _segmentTicks;
    private readonly int[] _counts;
    private readonly long[] _ids;
    private readonly object _gate = new();

    public SlidingWindowCounter(TimeSpan window, int segmentsPerWindow)
        : this(
            segmentsPerWindow,
            Math.Max(1, (long)(window.TotalSeconds / segmentsPerWindow * Stopwatch.Frequency)))
    {
    }

    public SlidingWindowCounter(int segmentsPerWindow, long segmentTicks)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(segmentsPerWindow, 2);
        ArgumentOutOfRangeException.ThrowIfLessThan(segmentTicks, 1);

        _segmentCount = segmentsPerWindow;
        _segmentTicks = segmentTicks;
        _counts = new int[segmentsPerWindow];
        _ids = new long[segmentsPerWindow];
        Array.Fill(_ids, -1);
    }

    /// <summary>Records one event and returns the count in the current window.</summary>
    public int Record() => Record(Stopwatch.GetTimestamp());

    public int Record(long nowTicks)
    {
        if (nowTicks < 0)
            nowTicks = 0;

        lock (_gate)
        {
            var currentId = nowTicks / _segmentTicks;
            var minId = currentId - _segmentCount + 1;
            var slot = (int)(currentId % _segmentCount);
            if (_ids[slot] != currentId)
            {
                _counts[slot] = 0;
                _ids[slot] = currentId;
            }

            _counts[slot]++;
            var total = 0;
            for (var i = 0; i < _segmentCount; i++)
            {
                if (_ids[i] >= minId)
                    total += _counts[i];
            }

            return total;
        }
    }
}
