namespace Dhcpr.Core.Linq;

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