using Microsoft.Extensions.ObjectPool;

namespace Dhcpr.Core.Linq;

public class ListPool<T>
{
    public static ObjectPool<PooledList<T>> Default { get; } = new DefaultObjectPool<PooledList<T>>(
        ListPoolObjectPolicy<T>.Default,
        maximumRetained: 1024
    );
}