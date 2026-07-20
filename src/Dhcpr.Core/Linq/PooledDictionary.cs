using System.Collections;
using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;

namespace Dhcpr.Core.Linq;

public sealed class PooledDictionary<TKey, TValue> : IDictionary<TKey, TValue>, IDisposable where TKey : notnull
{
    private long _token = 0;
    private int _estimatedCapacity;

    private static readonly List<int> Primes = new()
    {
        3, 7, 11, 17, 23, 29, 37, 47, 59, 71, 89, 107, 131, 163, 197, 239, 293, 353, 431, 521, 631, 761, 919,
        1103, 1327, 1597, 1931, 2333, 2801, 3371, 4049, 4861, 5839, 7013, 8419, 10103, 12143, 14591,
        17519, 21023, 25229, 30293, 36353, 43627, 52361, 62851, 75431, 90523, 108631, 130363, 156437,
        187751, 225307, 270371, 324449, 389357, 467237, 560689, 672827, 807403, 968897, 1162687, 1395263,
        1674319, 2009191, 2411033, 2893249, 3471899, 4166287, 4999559, 5999471, 7199369
    };

    private readonly Dictionary<TKey, TValue> _dictionaryImplementation = new();

    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    private int UpdateEstimatedCapacity()
    {
        if (Count > _estimatedCapacity)
            return _estimatedCapacity = EstimateCapacity(Count);

        return _estimatedCapacity;
    }

    private static int EstimateCapacity(int count)
    {
        var index = Primes.BinarySearch(count);
        if (index < 0)
            index = ~index;
        if (index >= Primes.Count)
            index = Primes.Count - 1;

        while (Primes[index] < count && Primes.Count > index)
            index++;

        return Primes[index];
    }


    public int EstimatedCapacity => UpdateEstimatedCapacity();

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
        DictionaryPool<TKey, TValue>.Default.Return(this);
    }

    public IEnumerator<KeyValuePair<TKey, TValue>> GetEnumerator()
    {
        return _dictionaryImplementation.GetEnumerator();
    }

    IEnumerator IEnumerable.GetEnumerator()
    {
        return ((IEnumerable)_dictionaryImplementation).GetEnumerator();
    }

    public void Add(KeyValuePair<TKey, TValue> item)
    {
        Add(item.Key, item.Value);
    }

    public void Clear()
    {
        _dictionaryImplementation.Clear();
    }

    public bool Contains(KeyValuePair<TKey, TValue> item)
    {
        return _dictionaryImplementation.Contains(item);
    }

    public void CopyTo(KeyValuePair<TKey, TValue>[] array, int arrayIndex)
    {
        ((ICollection)_dictionaryImplementation).CopyTo(array, arrayIndex);
    }

    public bool Remove(KeyValuePair<TKey, TValue> item)
    {
        return _dictionaryImplementation.Remove(item.Key);
    }

    public int Count => _dictionaryImplementation.Count;

    public bool IsReadOnly => false;

    public void Add(TKey key, TValue value)
    {
        _dictionaryImplementation.Add(key, value);
        UpdateEstimatedCapacity();
    }

    public bool ContainsKey(TKey key)
    {
        return _dictionaryImplementation.ContainsKey(key);
    }

    public bool Remove(TKey key)
    {
        return _dictionaryImplementation.Remove(key);
    }

    public bool TryGetValue(TKey key, [MaybeNullWhen(false)] out TValue value)
    {
        return _dictionaryImplementation.TryGetValue(key, out value);
    }

    public TValue this[TKey key]
    {
        get => _dictionaryImplementation[key];
        set
        {
            _dictionaryImplementation[key] = value;
            UpdateEstimatedCapacity();
        }
    }

    public ICollection<TKey> Keys => _dictionaryImplementation.Keys;

    public ICollection<TValue> Values => _dictionaryImplementation.Values;
}