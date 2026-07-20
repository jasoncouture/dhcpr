namespace Dhcpr.Core.Linq;

public sealed class PooledHashSet<T> : HashSet<T>, IDisposable
{
    private int _disposed;

    internal void Reset()
    {
        Clear();
        Volatile.Write(ref _disposed, 0);
    }

    public void Dispose()
    {
        if (Interlocked.Exchange(ref _disposed, 1) != 0)
            return;
        HashSetPool<T>.Default.Return(this);
    }
}
