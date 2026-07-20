namespace Dhcpr.Core.Linq;

public sealed class PooledList<T> : List<T>, IDisposable
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
        ListPool<T>.Default.Return(this);
    }
}
