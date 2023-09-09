using System.Text;

namespace Dhcpr.Dns.Core.Protocol;

public sealed record TextData(string Text) : IDomainResourceRecordData
{
    public int Size => Text.Length + 1;

    public void WriteTo(ref Span<byte> span)
    {
        DomainMessageEncoder.EncodeAndAdvance(ref span, (byte)Text.Length);
        DomainMessageEncoder.EncodeAndAdvance(ref span, Text);
    }

    public static IDomainResourceRecordData ReadFrom(ReadOnlySpan<byte> bytes)
    {
        var textLength = bytes[0];
        return new TextData(Encoding.ASCII.GetString(bytes[1..][..textLength]));
    }
}