using Microsoft.Extensions.ObjectPool;

namespace Dhcpr.Core.Linq;

public class DictionaryPool<TKey, TValue> where TKey : notnull
{
    static DictionaryPool()
    {
        Default = new DefaultObjectPool<PooledDictionary<TKey, TValue>>(
            DictionaryPoolObjectPolicy<TKey, TValue>.Default,
            maximumRetained: 1024
        );
    }

    public static ObjectPool<PooledDictionary<TKey, TValue>> Default { get; }
}