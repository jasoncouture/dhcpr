using System.Buffers;
using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;

namespace Dhcpr.Dhcp.Core.Protocol;

public record DhcpOption(DhcpOptionCode Code, ImmutableArray<byte> Payload)
{
    public override string ToString()
    {
        if (IsFixedSize(Code))
            return $"{Code:G}";
        
        return $"{Code:G}: {{ {BitConverter.ToString(Payload.ToArray()).Replace("-", " ")} }}";
    }

    private static bool IsFixedSize(DhcpOptionCode code)
    {
        return code is DhcpOptionCode.Pad or DhcpOptionCode.End;
    }

    private static int GetEncodedLength(DhcpOptionCode type, int payloadLength)
    {
        return sizeof(DhcpOptionCode) + (IsFixedSize(type) ? 0 : 1) + (IsFixedSize(type) ? 0 : payloadLength);
    }

    static DhcpOption()
    {
        StaticOptions[(byte)DhcpOptionCode.Pad] = new DhcpOption(DhcpOptionCode.Pad, ImmutableArray<byte>.Empty);
        StaticOptions[(byte)DhcpOptionCode.End] = new DhcpOption(DhcpOptionCode.End, ImmutableArray<byte>.Empty);
        StaticOptions[(byte)DhcpOptionCode.RapidCommit] =
            new DhcpOption(DhcpOptionCode.RapidCommit, ImmutableArray<byte>.Empty);
    }

    public int Length => GetEncodedLength(Code, Payload.Length);

    private static readonly DhcpOption?[] StaticOptions = new DhcpOption?[256];

    public static bool TryParse(ReadOnlySpan<byte> bytes, [NotNullWhen(true)] out DhcpOption? option)
    {
        option = null;
        if (bytes.Length == 0) return false;
        // Short circuit for options we know don't have a length byte, or any data.
        option = StaticOptions[bytes[0]];
        if (option is not null) return true;

        var code = (DhcpOptionCode)bytes[0];
        bytes = bytes[1..];


        if (bytes.Length == 0) return false;

        var length = bytes[0];

        bytes = bytes[1..];

        if (length > bytes.Length)
            return false;

        var payload = bytes[..length].ToImmutableArray();
        option = new DhcpOption(code, payload);
        return true;
    }

    public void WriteAndAdvance(ref Span<byte> buffer)
    {
        buffer[0] = (byte)Code;
        buffer = buffer[1..];
        if (IsFixedSize(Code)) return;
        buffer[0] = (byte)Length;
        buffer = buffer[1..];
        Payload.CopyTo(buffer);
        buffer = buffer[Payload.Length..];
    }
}