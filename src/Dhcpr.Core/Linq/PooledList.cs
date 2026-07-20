namespace Dhcpr.Core.Linq;

public sealed class PooledList<T> : List<T>, IDisposable
{
    private long _token;

    internal void Reset()
    {
        Clear();
        Interlocked.Exchange(ref _token, 0);
    }

    public void Dispose()
    {
        // 0 = in use / checked out; 1 = returned (or returning) to the pool.
        if (Interlocked.CompareExchange(ref _token, 1, 0) != 0)
            return;
        ListPool<T>.Default.Return(this);
    }
}
