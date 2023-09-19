using Microsoft.Extensions.ObjectPool;

namespace Dhcpr.Core.Linq;

internal sealed class HashSetPoolObjectPolicy<T> : IPooledObjectPolicy<PooledHashSet<T>>
{
    public PooledHashSet<T> Create()
    {
        return new PooledHashSet<T>();
    }
    public static HashSetPoolObjectPolicy<T> Default { get; } = new();
    public bool Return(PooledHashSet<T> obj)
    {
        obj.Reset();
        return true;
    }
}
internal sealed class ListPoolObjectPolicy<T> : IPooledObjectPolicy<PooledList<T>>
{
    public static ListPoolObjectPolicy<T> Default { get; } = new();

    public PooledList<T> Create()
    {
        return new PooledList<T>();
    }

    public bool Return(PooledList<T> obj)
    {
        obj.Reset();
        return true;
    }
}