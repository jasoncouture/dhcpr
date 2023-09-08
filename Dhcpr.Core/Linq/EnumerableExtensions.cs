namespace Dhcpr.Core.Linq;

public static class EnumerableExtensions
{
    public static IOrderedEnumerable<T> ThenShuffle<T>(this IOrderedEnumerable<T> enumerable) 
        => enumerable.ThenBy(i => Random.Shared.Next(0, int.MaxValue));

    public static IOrderedEnumerable<T> Shuffle<T>(this IEnumerable<T> enumerable) 
        => enumerable.OrderBy(i => Random.Shared.Next(0, int.MaxValue));
}