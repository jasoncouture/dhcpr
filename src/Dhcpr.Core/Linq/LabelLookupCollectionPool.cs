using Microsoft.Extensions.ObjectPool;

namespace Dhcpr.Core.Linq;

public static class LabelLookupCollectionPool<T> where T : class
{
    private static readonly ObjectPool<LabelLookupCollection<T>> Pool;

    private sealed class PoolPolicy : IPooledObjectPolicy<LabelLookupCollection<T>>
    {
        LabelLookupCollection<T> IPooledObjectPolicy<LabelLookupCollection<T>>.Create() => new();
        bool IPooledObjectPolicy<LabelLookupCollection<T>>.Return(LabelLookupCollection<T> obj) => true;
        public static IPooledObjectPolicy<LabelLookupCollection<T>> Instance { get; } = new PoolPolicy();
    }

    static LabelLookupCollectionPool() => Pool = new DefaultObjectPool<LabelLookupCollection<T>>(PoolPolicy.Instance);

    public static LabelLookupCollection<T> Get() => Pool.Get();

    public static void Return(LabelLookupCollection<T> collection) => Pool.Return(collection);
}