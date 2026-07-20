namespace Dhcpr.Core.Linq;

public sealed class PooledHashSet<T> : HashSet<T>, IDisposable
{
    private long _token;

    internal void Reset()
    {
        Clear();
        Interlocked.Exchange(ref _token, 0);
    }

    public void Dispose()
    {
        if (Interlocked.CompareExchange(ref _token, 1, 0) != 0)
            return;
        HashSetPool<T>.Default.Return(this);
    }
}
