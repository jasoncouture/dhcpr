using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Dhcpr.Core.Metrics;

public sealed class MetricPublisher : IMetricPublisher
{
    private const int MaxPooledWorkItems = 256;

    private readonly IMeterFactory _meterFactory;
    private readonly ConcurrentDictionary<string, Meter> _meters = new();

    public MetricPublisher(IMeterFactory meterFactory)
    {
        _meterFactory = meterFactory;
    }

    public IPublishedCounter CreateCounter(string meterName, string name, string? unit, string? description)
    {
        var counter = GetMeter(meterName).CreateCounter<long>(name, unit, description);
        return new PublishedCounter(this, counter);
    }

    public IPublishedHistogram CreateHistogram(
        string meterName,
        string name,
        string? unit,
        string? description,
        double[]? buckets = null)
    {
        var meter = GetMeter(meterName);
        var histogram = buckets is { Length: > 0 }
            ? meter.CreateHistogram<double>(
                name,
                unit,
                description,
                advice: new InstrumentAdvice<double> { HistogramBucketBoundaries = buckets })
            : meter.CreateHistogram<double>(name, unit, description);
        return new PublishedHistogram(this, histogram);
    }

    private Meter GetMeter(string meterName)
        => _meters.GetOrAdd(meterName, static (name, factory) => factory.Create(name), _meterFactory);

    private void EnqueueAdd(Counter<long> counter, long value, in TagList tags)
    {
        var item = CounterWorkItem.Rent();
        item.Assign(counter, value, tags);
        ThreadPool.UnsafeQueueUserWorkItem(item, preferLocal: false);
    }

    private void EnqueueRecord(Histogram<double> histogram, double value, in TagList tags)
    {
        var item = HistogramWorkItem.Rent();
        item.Assign(histogram, value, tags);
        ThreadPool.UnsafeQueueUserWorkItem(item, preferLocal: false);
    }

    private sealed class PublishedCounter(MetricPublisher publisher, Counter<long> counter) : IPublishedCounter
    {
        public void Add(long value, in TagList tags)
            => publisher.EnqueueAdd(counter, value, in tags);
    }

    private sealed class PublishedHistogram(MetricPublisher publisher, Histogram<double> histogram) : IPublishedHistogram
    {
        public void Record(double value, in TagList tags)
            => publisher.EnqueueRecord(histogram, value, in tags);
    }

    private sealed class CounterWorkItem : IThreadPoolWorkItem
    {
        private static readonly ConcurrentBag<CounterWorkItem> Pool = [];

        private Counter<long>? _counter;
        private long _value;
        private TagList _tags;

        public static CounterWorkItem Rent()
            => Pool.TryTake(out var item) ? item : new CounterWorkItem();

        public void Assign(Counter<long> counter, long value, in TagList tags)
        {
            _counter = counter;
            _value = value;
            _tags = tags;
        }

        public void Execute()
        {
            var counter = _counter;
            var value = _value;
            var tags = _tags;
            _counter = null;
            _tags = default;
            Return(this);
            counter!.Add(value, in tags);
        }

        private static void Return(CounterWorkItem item)
        {
            if (Pool.Count < MaxPooledWorkItems)
                Pool.Add(item);
        }
    }

    private sealed class HistogramWorkItem : IThreadPoolWorkItem
    {
        private static readonly ConcurrentBag<HistogramWorkItem> Pool = [];

        private Histogram<double>? _histogram;
        private double _value;
        private TagList _tags;

        public static HistogramWorkItem Rent()
            => Pool.TryTake(out var item) ? item : new HistogramWorkItem();

        public void Assign(Histogram<double> histogram, double value, in TagList tags)
        {
            _histogram = histogram;
            _value = value;
            _tags = tags;
        }

        public void Execute()
        {
            var histogram = _histogram;
            var value = _value;
            var tags = _tags;
            _histogram = null;
            _tags = default;
            Return(this);
            histogram!.Record(value, in tags);
        }

        private static void Return(HistogramWorkItem item)
        {
            if (Pool.Count < MaxPooledWorkItems)
                Pool.Add(item);
        }
    }
}
