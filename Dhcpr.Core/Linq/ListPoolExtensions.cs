namespace Dhcpr.Dns.Core;

public static class ListPoolExtensions
{
    public static PooledList<T> ToPooledList<T>(this IEnumerable<T> enumerable)
    {
        var ret = ListPool<T>.Default.Get();
        ret.AddRange(enumerable);

        return ret;
    }
}