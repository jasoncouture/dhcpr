using System.Text;

using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

public sealed record TextData(string Text) : IDomainResourceRecordData
{
    public int EstimatedSize => Text.Length + 1;

    public void WriteTo(ref DnsParsingSpan span)
    {
        DomainMessageEncoder.EncodeAndAdvance(ref span, (ushort)EstimatedSize);
        DomainMessageEncoder.EncodeAndAdvance(ref span, (byte)Text.Length);
        DomainMessageEncoder.EncodeAndAdvance(ref span, Text);
    }

    public static IDomainResourceRecordData ReadFrom(ref ReadOnlyDnsParsingSpan bytes, int dataLength)
    {
        var textLength = bytes[0];
        bytes = bytes[1..];
        var text = Encoding.ASCII.GetString(bytes[..textLength].CurrentSpan);
        bytes = bytes[textLength..];
        return new TextData(text);
    }
}