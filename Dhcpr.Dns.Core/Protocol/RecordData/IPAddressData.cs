using System.Net;
using System.Net.Sockets;

using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

public sealed record IPAddressData(IPAddress Address) : IDomainResourceRecordData
{
    public int Size => Address.AddressFamily == AddressFamily.InterNetwork ? 4 : 16;
    public void WriteTo(ref DnsParsingSpan span)
    {
        Address.TryWriteBytes(span, out var bytesWritten);
        span = span[bytesWritten..];
    }

    public static IDomainResourceRecordData ReadFrom(ReadOnlyDnsParsingSpan bytes)
    {
        return new IPAddressData(new IPAddress(bytes));
    }
}