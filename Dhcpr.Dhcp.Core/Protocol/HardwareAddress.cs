using System.Buffers;
using System.Collections.Immutable;

namespace Dhcpr.Dhcp.Core.Protocol;

public sealed record HardwareAddress(ImmutableArray<byte> Bytes, int Length)
{
    internal const int HardwareAddressMaxLength = 16;

    public static HardwareAddress ReadAndAdvance(ref ReadOnlySpan<byte> bytes, int length)
    {
        var ret = new HardwareAddress(bytes[..HardwareAddressMaxLength].ToImmutableArray(), length);
        bytes = bytes[HardwareAddressMaxLength..];
        return ret;
    }
    public override string ToString()
    {
        var array = ArrayPool<byte>.Shared.Rent(Length);
        try
        {
            Bytes.CopyTo(0, array, 0, Length);
            return BitConverter.ToString(array, 0, Length).Replace('-', ':').ToUpper();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(array);
        }
    }

    public void WriteAndAdvance(ref Span<byte> buffer)
    {
        var toCopy = Math.Min(Math.Min(Length, buffer.Length), HardwareAddressMaxLength);
        Bytes[..toCopy].CopyTo(buffer);
        buffer = buffer[16..];
    }
}