namespace Dhcpr.Core.Linq;

public sealed class PooledHashSet<T> : HashSet<T>, IDisposable
{
    private bool _disposed;

    internal void Reset()
    {
        Clear();
        _disposed = false;
    }

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        HashSetPool<T>.Default.Return(this);
    }
}
