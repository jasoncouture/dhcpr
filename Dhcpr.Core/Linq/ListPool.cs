using Microsoft.Extensions.ObjectPool;

namespace Dhcpr.Core.Linq;

public class ListPool<T>
{
    static ListPool()
    {
        Default = new DefaultObjectPool<PooledList<T>>(
            ListPoolObjectPolicy<T>.Default,
            maximumRetained: 1024
        );
    }

    public static ObjectPool<PooledList<T>> Default { get; }
}