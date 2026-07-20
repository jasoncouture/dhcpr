namespace Dhcpr.Core.Linq;

public sealed class PooledList<T> : List<T>, IDisposable
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
        ListPool<T>.Default.Return(this);
    }
}
