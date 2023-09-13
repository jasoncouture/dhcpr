using Dhcpr.Core.Linq;

namespace Dhcpr.Dns.Core.Protocol.Parser;

public ref struct DnsParsingSpan
{
    private readonly int _offset;
    private readonly Span<byte> _buffer;
    private readonly Span<byte> _start;
    private readonly PooledDictionary<string, int> _labels;

    public int Offset => _offset;

    // Welcome to my only spans.
    public Span<byte> Span => _buffer;
    public int Count => _buffer.Length;
    public byte this[Index index] => _buffer[index.GetOffset(Count)];

    public DnsParsingSpan this[Range range]
    {
        get
        {
            var (offset, length) = range.GetOffsetAndLength(Count);
            return Slice(offset, length + offset);
        }
    }

    public DnsParsingSpan(PooledDictionary<string, int> labels, Span<byte> buffer)
        : this(labels, buffer, buffer, 0)
    {
    }

    public DnsParsingSpan(PooledDictionary<string, int> labels, Span<byte> buffer, Span<byte> start, int offset)
    {
        _labels = labels;
        _buffer = buffer;
        _start = start;
        _offset = offset;
    }

    public bool TryGetOffset(string label, out int offset)
    {
        return _labels.TryGetValue(label.ToLowerInvariant(), out offset);
    }

    public void AddLabel(string label, int offset) => _labels.TryAdd(label.ToLowerInvariant(), offset);

    public DnsParsingSpan Slice(int start) => this[start..];

    public DnsParsingSpan Slice(int start, int end)
    {
        var newBuffer = _buffer[start..end];
        var newOffset = _offset + start;
        return new DnsParsingSpan(_labels, newBuffer, _start, newOffset);
    }

    public static implicit operator Span<byte>(DnsParsingSpan span)
    {
        return span._buffer;
    }

    public static implicit operator ReadOnlySpan<byte>(DnsParsingSpan span)
    {
        return span._buffer;
    }

    public static explicit operator ReadOnlyDnsParsingSpan(DnsParsingSpan span)
    {
        return new ReadOnlyDnsParsingSpan(span._buffer,
            span._start,
            span._offset);
    }
}