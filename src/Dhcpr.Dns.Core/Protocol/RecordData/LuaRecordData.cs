using System.Text;

using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

/// <summary>Private-use LUA zone record (PowerDNS-style presentation).</summary>
public sealed record LuaRecordData(string TargetType, string Script) : IDomainResourceRecordData
{
    public int EstimatedSize => 2 + Encoding.ASCII.GetByteCount(TargetType) + Encoding.ASCII.GetByteCount(Script);

    public void WriteTo(ref DnsParsingSpan span)
    {
        var origin = span;
        span = span[2..];
        WriteCharString(ref span, TargetType);
        WriteCharString(ref span, Script);
        DomainMessageEncoder.EncodeAndAdvance(ref origin, (ushort)(span.Offset - (origin.Offset + 2)));
    }

    public static IDomainResourceRecordData ReadFrom(ref ReadOnlyDnsParsingSpan bytes, int dataLength)
    {
        var targetType = ReadCharString(ref bytes);
        var script = ReadCharString(ref bytes);
        return new LuaRecordData(targetType, script);
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
