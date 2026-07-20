using Microsoft.Extensions.ObjectPool;

namespace Dhcpr.Core.Linq;

public static class HashSetPool<T>
{
    public static ObjectPool<PooledHashSet<T>> Default { get; } = new DefaultObjectPool<PooledHashSet<T>>(
        HashSetPoolObjectPolicy<T>.Default,
        maximumRetained: 1024
    );
}