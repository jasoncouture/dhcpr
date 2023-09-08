using Microsoft.Extensions.ObjectPool;

namespace Dhcpr.Core.Linq;

internal sealed class ListPoolObjectPolicy<T> : IPooledObjectPolicy<PooledList<T>>
{
    private readonly int _maxCapacity;

    public ListPoolObjectPolicy(int maxCapacity)
    {
        _maxCapacity = maxCapacity;
    }

    public static ListPoolObjectPolicy<T> Default { get; } = new(4096);

    public PooledList<T> Create()
    {
        return new PooledList<T>();
    }

    public bool Return(PooledList<T> obj)
    {
        if (obj.Capacity > 4096)
        {
            obj.Discard();
        }

        obj.Reset();
        return true;
    }
}