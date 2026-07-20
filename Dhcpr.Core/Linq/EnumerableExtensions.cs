namespace Dhcpr.Core.Linq;

public static class EnumerableExtensions
{
    public static IOrderedEnumerable<T> ThenShuffle<T>(this IOrderedEnumerable<T> enumerable)
        => enumerable.ThenBy(i => Random.Shared.Next(0, int.MaxValue));
}