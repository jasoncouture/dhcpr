namespace Dhcpr.Dns.Core.Protocol.Parser;

public readonly ref struct ReadOnlyDnsParsingSpan
{
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
        Offset = offset;
    }

    public ReadOnlyDnsParsingSpan Slice(int start)
    {
        var newBuffer = this[start..];

        return newBuffer;
    }

    public ReadOnlyDnsParsingSpan Slice(int start, int end) => new(_buffer[start..end], _start, Offset + start);

    public static implicit operator ReadOnlySpan<byte>(ReadOnlyDnsParsingSpan span) => span._buffer;

    public ReadOnlyDnsParsingSpan FromStart() => new(_start);
    public int Offset { get; }
}