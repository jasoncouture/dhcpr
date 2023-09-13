using System.Diagnostics.CodeAnalysis;

using Dhcpr.Core.Linq;

namespace Dhcpr.Dns.Core.Protocol.Parser;

public ref struct ReadOnlyDnsParsingSpan
{
    private readonly int _offset;
    private readonly ReadOnlySpan<byte> _buffer;
    private readonly ReadOnlySpan<byte> _start;
    public ReadOnlySpan<byte> Span => _buffer;
    public int Count => _buffer.Length;
    public byte this[Index index] => _buffer[index.GetOffset(Count)];

    public ReadOnlyDnsParsingSpan this[Range range]
    {
        get
        {
            var (offset, length) = range.GetOffsetAndLength(Count);
            return Slice(offset, length + offset);
        }
    }

    public ReadOnlyDnsParsingSpan(ReadOnlySpan<byte> buffer)
        : this(buffer, Span<byte>.Empty, 0)
    {
        var start = new byte[buffer.Length].AsSpan();
        buffer.CopyTo(start);
        _start = start;
    }

    public ReadOnlyDnsParsingSpan(ReadOnlySpan<byte> buffer,
        ReadOnlySpan<byte> start, int offset)
    {
        _buffer = buffer;
        _start = start;
        _offset = offset;
    }

    public ReadOnlyDnsParsingSpan Slice(int start)
    {
        var newBuffer = this[start..];

        return newBuffer;
    }

    public ReadOnlyDnsParsingSpan Slice(int start, int end) => new(_buffer[start..end], _start, _offset + start);

    public static implicit operator ReadOnlySpan<byte>(ReadOnlyDnsParsingSpan span) => span._buffer;

    public ReadOnlyDnsParsingSpan FromStart() => new(_start);
    public int Offset => _offset;
}

public class LabelTree<TValue>
{
    private LabelTreeEntry<TValue> _root = new()
    {
        Label = string.Empty
    };
    public bool TryAdd(string[] keyPath, TValue value)
    {
        LabelTreeEntry<TValue>? nextChild = _root;
        // TODO
        throw new NotImplementedException();
    }
}

[SuppressMessage("ReSharper", "StaticMemberInGenericType")]
public class LabelTreeEntry<TValue> : IComparable<string>, IDisposable
{
    public required string Label { get; init; } = string.Empty;
    public TValue Value { get; init; } = default!;

    private PooledList<LabelTreeEntry<TValue>> _children = ListPool<LabelTreeEntry<TValue>>.Default.Get();
    private PooledList<string> _childrenKeys = ListPool<string>.Default.Get();


    public int CompareTo(string? other)
    {
        ArgumentException.ThrowIfNullOrEmpty(other);
        return string.Compare(Label, other, StringComparison.OrdinalIgnoreCase);
    }

    private int GetIndex(string key)
    {
        var index = _childrenKeys.BinarySearch(key, StringComparer.OrdinalIgnoreCase);
        return index;
    }
    
    public bool TryAdd(string key, TValue value)
    {
        var index = GetIndex(key);
        if (index >= 0)
            return false;
        var insertIndex = ~index;
        _childrenKeys.Insert(insertIndex, key);
        _children.Insert(insertIndex, new LabelTreeEntry<TValue>() { Label = key, Value = value });
        return true;
    }

    private static readonly ThreadLocal<Stack<LabelTreeEntry<TValue>>> PooledChildStacks =
        new(() => new Stack<LabelTreeEntry<TValue>>());

    private static readonly ThreadLocal<Stack<string>> PooledLabelStacks = new(() => new Stack<string>());

    public bool TryGetValue(IList<string> labels, [MaybeNullWhen(false)] out TValue value)
    {
        value = default;
        if (!TryGetChild(labels, out var child))
            return false;

        value = child.Value;

        return true;
    }

    internal bool TryGetChild(IList<string> keyPath, [MaybeNullWhen(false)] out LabelTreeEntry<TValue> child)
    {
        child = default;
        LabelTreeEntry<TValue>? nextChild = this;
        for (var x = 1; x <= keyPath.Count; x++)
        {
            var nextLabel = keyPath[^x];

            if (!nextChild.TryGetChild(nextLabel, out nextChild))
                return false;
        }

        child = nextChild;
        return true;
    }

    internal bool TryGetChild(string key, [MaybeNullWhen(false)] out LabelTreeEntry<TValue> child)
    {
        child = default;
        var index = GetIndex(key);
        if (index < 0)
            return false;

        child = _children[index];
        return true;
    }
    public bool TryGetValue(string key, [MaybeNullWhen(false)] out TValue value)
    {
        var ret = TryGetChild(key, out var child);
        value = child switch
        {
            not null => child.Value,
            _ => default(TValue)
        };
        return ret;
    }

    public void Dispose()
    {
        _children.Dispose();
        GC.SuppressFinalize(this);
    }
}