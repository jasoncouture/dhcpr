using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;

namespace Dhcpr.Core.Linq;

public sealed class LabelLookupCollection<T> : IDisposable where T : class
{
    private readonly Dictionary<string, LabelLookupCollection<T>> _items = new(StringComparer.OrdinalIgnoreCase);

    internal LabelLookupCollection() { }

    private T? Value { get; set; }
    public bool TryGetNearestValue(
        IReadOnlyList<string> labels,
        [NotNullWhen(true)] out T? value
    )
    {
        value = null;
        var current = this;
        int index = 0;
        while (index < labels.Count)
        {
            var nextLabel = labels[labels.Count - index - 1];
            if (!current!._items.TryGetValue(nextLabel, out var next))
                return value is not null;
            value = next.Value ?? value;
            current = next;
            index++;
        }

        value = current.Value ?? value;
        return value is not null;
    }

    public bool TryGetValue(IReadOnlyList<string> labels, [NotNullWhen(true)] out T? value)
    {
        value = null;
        var current = this;
        int index = 0;
        while (index < labels.Count)
        {
            var nextLabel = labels[labels.Count - index - 1];
            if (!current!._items.TryGetValue(nextLabel, out var next))
                return false;
            current = next;
            index++;
        }

        value = current.Value;
        return value is not null;
    }

    public void GetOrAdd(string[] labels, Func<T> creationCallback)
    {
        if (TryGetValue(labels, out var ret)) return;
        var value = creationCallback.Invoke();
        TryAdd(labels, value);
    }

    public async ValueTask<T> GetOrAddAsync(string[] labels, Func<CancellationToken, Task<T>> creationCallback,
        CancellationToken cancellationToken)
    {
        if (TryGetValue(labels, out var ret)) return ret;
        var value = await creationCallback.Invoke(cancellationToken);
        TryAdd(labels, value);
        return value;
    }

    public void AddOrUpdate(IReadOnlyList<string> labels, T value, Func<T, T, T> updateFunction)
    {
        var current = this;
        int index = 0;
        while (index < labels.Count)
        {
            var nextLabel = labels[labels.Count - index - 1];
            if (!current!._items.TryGetValue(nextLabel, out var next))
                current._items.Add(nextLabel, next = LabelLookupCollectionPool<T>.Get());
            current = next;
            index++;
        }

        if (current.Value is not null)
        {
            current.Value = updateFunction.Invoke(current.Value, value);
            return;
        }

        current.Value = value;
    }

    public bool TryAdd(IReadOnlyList<string> labels, T value)
    {
        var current = this;
        int index = 0;
        while (index < labels.Count)
        {
            var nextLabel = labels[labels.Count - index - 1];
            if (!current!._items.TryGetValue(nextLabel, out var next))
                current._items.Add(nextLabel, next = LabelLookupCollectionPool<T>.Get());
            current = next;
            index++;
        }

        if (current.Value is not null)
            return false;

        current.Value = value;
        return true;
    }

    public void PruneTree()
    {
        foreach (var (key, value) in _items.ToImmutableArray())
        {
            value.PruneTree();

            if (value._items.Count != 0 || value.Value is not null)
            {
                continue;
            }

            _items.Remove(key);
            value.Dispose();
        }
    }

    public bool TryRemove(IReadOnlyList<string> labels)
    {
        var current = this;
        int index = 0;
        while (index < labels.Count)
        {
            var nextLabel = labels[labels.Count - index - 1];
            if (!current!._items.TryGetValue(nextLabel, out var next))
                return false;
            current = next;
            index++;
        }

        current.PruneTree();

        if (current.Value is null)
        {
            return false;
        }

        current.Value = null;

        return true;
    }

    public void Dispose()
    {
        var values = _items.Values;
        var valueDisposable = Value as IDisposable;
        Value = null;
        valueDisposable?.Dispose();
        _items.Clear();

        foreach (var value in values)
            value.Dispose();

        LabelLookupCollectionPool<T>.Return(this);
    }
}