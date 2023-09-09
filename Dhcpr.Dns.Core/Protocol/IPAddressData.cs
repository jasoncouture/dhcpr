using System.Net;
using System.Net.Sockets;

namespace Dhcpr.Dns.Core.Protocol;

public sealed record IPAddressData(IPAddress Address) : IDomainResourceRecordData
{
    public int Size => Address.AddressFamily == AddressFamily.InterNetwork ? 4 : 16;
    public void WriteTo(ref Span<byte> span)
    {
        Address.TryWriteBytes(span, out var bytesWritten);
        span = span[bytesWritten..];
    }

    public static IDomainResourceRecordData ReadFrom(ReadOnlySpan<byte> bytes)
    {
        return new IPAddressData(new IPAddress(bytes));
    }
}