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
        if (
            Interlocked.CompareExchange(
                ref _token,
                0,
                1) != 0
        ) return;
        ListPool<T>.Default.Return(this);
    }
}