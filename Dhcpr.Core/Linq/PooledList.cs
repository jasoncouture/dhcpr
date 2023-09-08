namespace Dhcpr.Core.Linq;

public sealed class PooledList<T> : List<T>, IDisposable
{
    private long _token = 0;

    internal void Discard()
    {
        Interlocked.Exchange(ref _token, 1);
    }

    internal void Reset()
    {
        Clear();
        Interlocked.Exchange(ref _token, 0);
    }

    public void Dispose()
    {
        Dispose(true);
    }

    private void Dispose(bool disposing)
    {
        if (
            Interlocked.CompareExchange(
                ref _token,
                0,
                1) != 0
        ) return;
        if (disposing)
        {
            ListPool<T>.Default.Return(this);
        }
    }

    ~PooledList()
    {
        Dispose(false);
    }
}