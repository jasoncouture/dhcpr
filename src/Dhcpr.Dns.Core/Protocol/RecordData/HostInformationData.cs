using System.Text;

using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

public sealed record HostInformationData(string Cpu, string OperatingSystem) : IDomainResourceRecordData
{
    public int EstimatedSize => 2 + Encoding.ASCII.GetByteCount(Cpu) + Encoding.ASCII.GetByteCount(OperatingSystem);

    public void WriteTo(ref DnsParsingSpan span)
    {
        var origin = span;
        span = span[2..];
        WriteCharString(ref span, Cpu);
        WriteCharString(ref span, OperatingSystem);
        DomainMessageEncoder.EncodeAndAdvance(ref origin, (ushort)(span.Offset - (origin.Offset + 2)));
    }

    public static IDomainResourceRecordData ReadFrom(ref ReadOnlyDnsParsingSpan bytes, int dataLength)
    {
        var cpu = ReadCharString(ref bytes);
        var os = ReadCharString(ref bytes);
        return new HostInformationData(cpu, os);
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
