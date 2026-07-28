using System.Text;

using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

public sealed record CertificationAuthorityAuthorizationData(byte Flags, string Tag, string Value)
    : IDomainResourceRecordData
{
    public int EstimatedSize => 2 + Encoding.ASCII.GetByteCount(Tag) + Encoding.ASCII.GetByteCount(Value);

    public void WriteTo(ref DnsParsingSpan span)
    {
        var origin = span;
        span = span[2..];
        DomainMessageEncoder.EncodeAndAdvance(ref span, Flags);
        var tagBytes = Encoding.ASCII.GetBytes(Tag);
        DomainMessageEncoder.EncodeAndAdvance(ref span, (byte)tagBytes.Length);
        tagBytes.CopyTo(span);
        span = span[tagBytes.Length..];
        var valueBytes = Encoding.ASCII.GetBytes(Value);
        valueBytes.CopyTo(span);
        span = span[valueBytes.Length..];
        DomainMessageEncoder.EncodeAndAdvance(ref origin, (ushort)(span.Offset - (origin.Offset + 2)));
    }

    public static IDomainResourceRecordData ReadFrom(ref ReadOnlyDnsParsingSpan bytes, int dataLength)
    {
        var flags = DomainMessageEncoder.ReadByteAndAdvance(ref bytes);
        var tagLength = DomainMessageEncoder.ReadByteAndAdvance(ref bytes);
        var tag = Encoding.ASCII.GetString(bytes.CurrentSpan[..tagLength]);
        bytes = bytes[tagLength..];
        var valueLength = dataLength - 2 - tagLength;
        var value = Encoding.ASCII.GetString(bytes.CurrentSpan[..valueLength]);
        bytes = bytes[valueLength..];
        return new CertificationAuthorityAuthorizationData(flags, tag, value);
    }
}
