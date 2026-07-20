using System.Collections.Concurrent;

using Dhcpr.Core.Linq;

namespace Dhcpr.Core;

public abstract class TypedSubscriber<TData> : ISubscriber
{
    private readonly ConcurrentBag<Func<object, TData, bool>> _filters;

    protected TypedSubscriber()
    {
        _filters = new ConcurrentBag<Func<object, TData, bool>>();
    }

    protected TypedSubscriber(ConcurrentBag<Func<object, TData, bool>> filters)
    {
        _filters = filters;
    }

    protected void AddFilter(Func<object, TData, bool> filter)
    {
        _filters.Add(filter);
    }

    protected abstract ValueTask OnMessageAsync(object sender, TData data, CancellationToken cancellationToken);

    public async ValueTask OnMessageAsync(object sender, object data, CancellationToken cancellationToken)
    {
        if (data is not TData typedData)
            return;
        if (!FilterMessage(sender, typedData)) return;
        await OnMessageAsync(sender, typedData, cancellationToken);
    }

    private bool FilterMessage(object sender, TData typedData)
    {
        if (_filters.Count == 0) return true;
        using var filters = _filters.ToPooledList();
        if (filters.Count == 0) return true;

        return filters.Any(filter => filter.Invoke(sender, typedData));
    }
}