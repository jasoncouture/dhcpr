using System.Net;
using System.Net.Sockets;

using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

public sealed record IPAddressData(IPAddress Address) : IDomainResourceRecordData
{
    public int EstimatedSize => Address.AddressFamily == AddressFamily.InterNetwork ? 4 : 16;

    public void WriteTo(ref DnsParsingSpan span)
    {
        DomainMessageEncoder.EncodeAndAdvance(ref span, (ushort)EstimatedSize);
        Address.TryWriteBytes(span, out var bytesWritten);
        span = span[bytesWritten..];
    }

    public static IDomainResourceRecordData ReadFrom(ref ReadOnlyDnsParsingSpan bytes, int dataLength)
    {
        var ret = new IPAddressData(new IPAddress(bytes.CurrentSpan[..dataLength]));
        bytes = bytes[dataLength..];
        return ret;
    }
}