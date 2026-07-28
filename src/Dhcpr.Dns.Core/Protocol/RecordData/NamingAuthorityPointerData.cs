using System.Text;

using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

public sealed record NamingAuthorityPointerData(
    ushort Order,
    ushort Preference,
    string Flags,
    string Services,
    string Regexp,
    DomainLabels Replacement) : IDomainResourceRecordData
{
    public int EstimatedSize =>
        4 + 3 + Encoding.ASCII.GetByteCount(Flags) + Encoding.ASCII.GetByteCount(Services) +
        Encoding.ASCII.GetByteCount(Regexp) + Replacement.EstimatedSize;

    public void WriteTo(ref DnsParsingSpan span)
    {
        var origin = span;
        span = span[2..];
        DomainMessageEncoder.EncodeAndAdvance(ref span, Order);
        DomainMessageEncoder.EncodeAndAdvance(ref span, Preference);
        WriteCharString(ref span, Flags);
        WriteCharString(ref span, Services);
        WriteCharString(ref span, Regexp);
        DomainMessageEncoder.EncodeAndAdvance(ref span, Replacement);
        DomainMessageEncoder.EncodeAndAdvance(ref origin, (ushort)(span.Offset - (origin.Offset + 2)));
    }

    public static IDomainResourceRecordData ReadFrom(ref ReadOnlyDnsParsingSpan bytes, int dataLength)
    {
        var order = DomainMessageEncoder.ReadUnsignedShortAndAdvance(ref bytes);
        var preference = DomainMessageEncoder.ReadUnsignedShortAndAdvance(ref bytes);
        var flags = ReadCharString(ref bytes);
        var services = ReadCharString(ref bytes);
        var regexp = ReadCharString(ref bytes);
        var replacement = DomainMessageEncoder.ReadLabelsAndAdvance(ref bytes);
        return new NamingAuthorityPointerData(order, preference, flags, services, regexp, replacement);
    }

    private static void WriteCharString(ref DnsParsingSpan span, string value)
    {
        var byteCount = Encoding.ASCII.GetByteCount(value);
        DomainMessageEncoder.EncodeAndAdvance(ref span, (byte)byteCount);
        DomainMessageEncoder.EncodeAndAdvance(ref span, value);
    }

    private static string ReadCharString(ref ReadOnlyDnsParsingSpan bytes)
    {
        var length = bytes[0];
        bytes = bytes[1..];
        var text = Encoding.ASCII.GetString(bytes.CurrentSpan[..length]);
        bytes = bytes[length..];
        return text;
    }
}
