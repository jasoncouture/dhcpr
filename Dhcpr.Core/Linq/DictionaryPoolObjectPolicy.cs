using Microsoft.Extensions.ObjectPool;

namespace Dhcpr.Core.Linq;

internal sealed class DictionaryPoolObjectPolicy<TKey, TValue> : IPooledObjectPolicy<PooledDictionary<TKey, TValue>>
    where TKey : notnull
{
    private const int MaxCapacity = 4096;

    public static IPooledObjectPolicy<PooledDictionary<TKey, TValue>> Default { get; } =
        new DictionaryPoolObjectPolicy<TKey, TValue>();

    private DictionaryPoolObjectPolicy() { }

    public PooledDictionary<TKey, TValue> Create() => new();

    public bool Return(PooledDictionary<TKey, TValue> obj)
    {
        // I wish we knew the actual capacity.
        // But this will have to do. We'll limit pool capacity anyway.
        if (obj.EstimatedCapacity > MaxCapacity)
        {
            return false;
        }
        obj.Reset();
        return true;
    }
}