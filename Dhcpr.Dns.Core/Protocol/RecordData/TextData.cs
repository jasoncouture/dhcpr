using System.Text;

using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

public sealed record TextData(string Text) : IDomainResourceRecordData
{
    public int Size => Text.Length + 1;

    public void WriteTo(ref DnsParsingSpan span)
    {
        DomainMessageEncoder.EncodeAndAdvance(ref span, (byte)Text.Length);
        DomainMessageEncoder.EncodeAndAdvance(ref span, Text);
    }

    public static IDomainResourceRecordData ReadFrom(ReadOnlyDnsParsingSpan bytes)
    {
        var textLength = bytes[0];
        return new TextData(Encoding.ASCII.GetString(bytes[1..textLength]));
    }
}