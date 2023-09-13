using Microsoft.Extensions.ObjectPool;

namespace Dhcpr.Core.Linq;

internal sealed class ListPoolObjectPolicy<T> : IPooledObjectPolicy<PooledList<T>>
{
    private const int MaxCapacity = 4096;

    public ListPoolObjectPolicy()
    {
    }

    public static ListPoolObjectPolicy<T> Default { get; } = new();

    public PooledList<T> Create()
    {
        return new PooledList<T>();
    }

    public bool Return(PooledList<T> obj)
    {
        if (obj.Capacity > MaxCapacity)
        {
            obj.Discard();
        }

        obj.Reset();
        return true;
    }
}