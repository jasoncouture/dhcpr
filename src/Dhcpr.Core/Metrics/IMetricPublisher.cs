using System.Diagnostics;
using System.Diagnostics.Metrics;

namespace Dhcpr.Core.Metrics;

/// <summary>
/// Process-bound owner of <see cref="System.Diagnostics.Metrics"/> instruments.
/// Call sites never hold a <see cref="Meter"/>, <see cref="Counter{T}"/>, or
/// <see cref="Histogram{T}"/>.
/// </summary>
public interface IMetricPublisher
{
    IPublishedCounter CreateCounter(string meterName, string name, string? unit, string? description);

    IPublishedHistogram CreateHistogram(
        string meterName,
        string name,
        string? unit,
        string? description,
        double[]? buckets = null);
}

public interface IPublishedCounter
{
    void Add(long value, in TagList tags);
}

public interface IPublishedHistogram
{
    void Record(double value, in TagList tags);
}
