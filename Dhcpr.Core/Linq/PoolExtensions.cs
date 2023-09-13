namespace Dhcpr.Core.Linq;

public static class PoolExtensions
{
    public static PooledDictionary<TKey, TValue> ToPooledDictionary<TKey, TValue>(
        this IEnumerable<KeyValuePair<TKey, TValue>> enumerable
    ) where TKey : notnull
    {
        return enumerable.ToPooledDictionary(
            static k => k.Key,
            static k => k.Value
        );
    }

    public static PooledDictionary<TKey, TValue> ToPooledDictionary<TKey, TValue>(
        this IEnumerable<TValue> enumerable,
        Func<TValue, TKey> keySelector
    ) where TKey : notnull
    {
        return enumerable.ToPooledDictionary(keySelector, static v => v);
    }


    public static PooledDictionary<TKey, TValue> ToPooledDictionary<TKey, TValue, T>(
        this IEnumerable<T> enumerable,
        Func<T, TKey> keySelector,
        Func<T, TValue> valueSelector
    ) where TKey : notnull
    {
        var ret = DictionaryPool<TKey, TValue>.Default.Get();

        foreach (var item in enumerable)
            ret.Add(keySelector.Invoke(item), valueSelector.Invoke(item));

        return ret;
    }

    public static PooledList<T> ToPooledList<T>(this IEnumerable<T> enumerable)
    {
        var ret = ListPool<T>.Default.Get();
        ret.AddRange(enumerable);

        return ret;
    }
}