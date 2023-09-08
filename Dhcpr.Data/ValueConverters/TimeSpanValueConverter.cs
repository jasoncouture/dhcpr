using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace Dhcpr.Data.ValueConverters;

public class TimeSpanValueConverter : ValueConverter<TimeSpan, double>
{
    public TimeSpanValueConverter() : base(t => t.TotalSeconds, d => TimeSpan.FromSeconds(d))
    {
    }

    public static TimeSpanValueConverter Instance { get; } = new();
}