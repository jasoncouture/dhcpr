using System.Collections.Immutable;

namespace Dhcpr.Dhcp.Core.Protocol;

public sealed record HardwareAddress(ImmutableArray<byte> Bytes, int Length)
{
    public override string ToString()
    {
        var slicedBytes = Bytes[..Length].ToArray();
        return BitConverter.ToString(slicedBytes).Replace('-', ':').ToUpper();
    }
}