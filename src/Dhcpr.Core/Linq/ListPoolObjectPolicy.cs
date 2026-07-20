using Microsoft.Extensions.ObjectPool;

namespace Dhcpr.Core.Linq;

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