using System.Diagnostics;
using System.Diagnostics.Metrics;

using Dhcpr.Core.Metrics;

using Microsoft.Extensions.DependencyInjection;

namespace Dhcpr.Core.UnitTests;

public class MetricPublisherTests
{
    [Fact]
    public void IncrementIsObserved()
    {
        long observed = 0;
        using var listener = Listen(
            "test.meter",
            "test.counter",
            (Action<long>)(value => Interlocked.Add(ref observed, value)));
        var publisher = CreatePublisher();
        var counter = publisher.CreateCounter("test.meter", "test.counter", "{n}", "test");

        var tags = new TagList { { "k", "v" } };
        counter.Add(3, in tags);

        Assert.True(SpinWait.SpinUntil(() => Volatile.Read(ref observed) == 3, TimeSpan.FromSeconds(2)));
    }

    [Fact]
    public void RecordIsObserved()
    {
        double observed = 0;
        using var listener = Listen(
            "test.meter",
            "test.histogram",
            (Action<double>)(value => Volatile.Write(ref observed, value)));
        var publisher = CreatePublisher();
        var histogram = publisher.CreateHistogram("test.meter", "test.histogram", "s", "test");

        var tags = new TagList { { "k", "v" } };
        histogram.Record(0.025, in tags);

        Assert.True(SpinWait.SpinUntil(() => Volatile.Read(ref observed) == 0.025, TimeSpan.FromSeconds(2)));
    }

    private static IMetricPublisher CreatePublisher()
    {
        var services = new ServiceCollection();
        services.AddMetrics();
        services.AddSingleton<IMetricPublisher, MetricPublisher>();
        return services.BuildServiceProvider().GetRequiredService<IMetricPublisher>();
    }

    private static MeterListener Listen(string meterName, string instrumentName, Delegate onMeasurement)
    {
        var listener = new MeterListener();
        listener.InstrumentPublished = (instrument, meterListener) =>
        {
            if (instrument.Meter.Name == meterName && instrument.Name == instrumentName)
                meterListener.EnableMeasurementEvents(instrument);
        };
        if (onMeasurement is Action<long> onLong)
        {
            listener.SetMeasurementEventCallback<long>((_, measurement, _, _) => onLong(measurement));
        }
        else if (onMeasurement is Action<double> onDouble)
        {
            listener.SetMeasurementEventCallback<double>((_, measurement, _, _) => onDouble(measurement));
        }

        listener.Start();
        return listener;
    }
}
