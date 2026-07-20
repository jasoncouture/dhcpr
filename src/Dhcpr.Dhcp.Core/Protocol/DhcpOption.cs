using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Dhcpr.Dhcp.Core.Protocol;

public sealed record DhcpOption(DhcpOptionCode Code, ImmutableArray<byte> Payload)
{
    public DhcpOption(DhcpOptionCode code, string str) : this(code, EncodeString(str))
    {
    }


    private static ImmutableArray<byte> EncodeString(string str)
    {
        var bufferSize = Encoding.ASCII.GetMaxByteCount(str.Length) + 1;
        Span<byte> buffer = stackalloc byte[bufferSize];
        Encoding.ASCII.GetBytes(str, buffer);
        return buffer.ToImmutableArray();
    }

    public DhcpOption(DhcpOptionCode code, IPAddress address) : this(code, EncodeIPAddress(address))
    {
    }

    private static ImmutableArray<byte> EncodeIPAddress(IPAddress address)
    {
        if (address.AddressFamily != AddressFamily.InterNetwork)
            throw new ArgumentException("Only IPv4 addresses are supported", nameof(address));
        Span<byte> addressBytes = stackalloc byte[4];
        address.TryWriteBytes(addressBytes, out _);
        return addressBytes.ToImmutableArray();
    }

    public DhcpOption(DhcpOptionCode code, IEnumerable<byte> bytes) : this(code, bytes.ToImmutableArray())
    {
    }

    public DhcpOption(DhcpOptionCode code, byte b) : this(code, new[] { b }.ToImmutableArray())
    {
    }

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

    public static DhcpOption End => StaticOptions[(byte)DhcpOptionCode.End]!;
    public static DhcpOption Pad => StaticOptions[(byte)DhcpOptionCode.Pad]!;
    public static DhcpOption RapidCommit => StaticOptions[(byte)DhcpOptionCode.RapidCommit]!;

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
        if (IsFixedSize(Code))
            return;


        buffer[0] = (byte)Payload.Length;
        buffer = buffer[1..];
        Payload.CopyTo(buffer);
        buffer = buffer[Payload.Length..];
    }
}