using Microsoft.Extensions.ObjectPool;

namespace Dhcpr.Core.Linq;

public class ListPool<T>
{
    public static ObjectPool<PooledList<T>> Default { get; } = new DefaultObjectPool<PooledList<T>>(
        ListPoolObjectPolicy<T>.Default,
        maximumRetained: 1024
    );
}

public sealed class PooledHashSet<T> : HashSet<T>, IDisposable
{
    private long _state = 0;

    internal void Reset()
    {
        Clear();
        Interlocked.Exchange(ref _state, 0);
    }
    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _state, 1, 0) != 0)
            return;
        HashSetPool<T>.Default.Return(this);
    }
}

public static class Pool
{
    public static PooledHashSet<T> GetHashSet<T>() => HashSetPool<T>.Default.Get();
    public static PooledList<T> GetList<T>() => ListPool<T>.Default.Get();

    public static void Return<T>(PooledHashSet<T> set) => HashSetPool<T>.Default.Return(set);
    public static void Return<T>(PooledList<T> set) => ListPool<T>.Default.Return(set);
}
public static class HashSetPool<T>
{
    public static ObjectPool<PooledHashSet<T>> Default { get; } = new DefaultObjectPool<PooledHashSet<T>>(
        HashSetPoolObjectPolicy<T>.Default,
        maximumRetained: 1024
    );
}