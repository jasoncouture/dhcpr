using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

namespace Dhcpr.Data.ValueConverters;

public sealed class UnixTimestampValueConverter : ValueConverter<DateTimeOffset, long>
{
    public UnixTimestampValueConverter()
        : base
        (
            s => s.ToUnixTimeMilliseconds(),
            s => DateTimeOffset.FromUnixTimeMilliseconds(s)
        )
    {
    }

    public static UnixTimestampValueConverter Instance { get; } = new();
}