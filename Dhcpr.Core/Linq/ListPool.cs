using Microsoft.Extensions.ObjectPool;

namespace Dhcpr.Core.Linq;

public class ListPool<T>
{
    static ListPool()
    {
        Default = ObjectPool.Create(ListPoolObjectPolicy<T>.Default);
    }

    public static ObjectPool<PooledList<T>> Default { get; }
}