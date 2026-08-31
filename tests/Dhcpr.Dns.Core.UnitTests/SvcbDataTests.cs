using System.Net;

using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Parser;
using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.UnitTests;

public class SvcbDataTests
{
    [Fact]
    public void RoundTripsPriorityTargetAndParameters()
    {
        var data = new SvcbData(
            1,
            new DomainLabels("dns.example.com"),
            [
                SvcbParameter.Alpn("h2", "h3"),
                SvcbParameter.Port(443),
                SvcbParameter.DohPath("/dns-query{?dns}"),
                SvcbParameter.Ipv4Hint(IPAddress.Parse("192.0.2.1")),
                SvcbParameter.Ipv6Hint(IPAddress.Parse("2001:db8::1")),
            ]);

        var decoded = RoundTrip(data);

        Assert.Equal(1, decoded.Priority);
        Assert.Equal("dns.example.com", decoded.TargetName.ToString());
        Assert.Equal(5, decoded.Parameters.Length);
        Assert.Contains(decoded.Parameters, p => p.Key is SvcbParameterKey.Alpn);
        Assert.Contains(decoded.Parameters, p => p.Key is SvcbParameterKey.Port);
        Assert.Contains(decoded.Parameters, p => p.Key is SvcbParameterKey.DohPath);
        Assert.Contains(decoded.Parameters, p => p.Key is SvcbParameterKey.Ipv4Hint);
        Assert.Contains(decoded.Parameters, p => p.Key is SvcbParameterKey.Ipv6Hint);
    }

    [Fact]
    public void TargetNameIsNotCompressedAgainstOwner()
    {
        var target = new DomainLabels("_dns.resolver.arpa");
        var data = new SvcbData(1, target);
        var buffer = new byte[256];
        using var dict = DictionaryPool<string, int>.Default.Get();
        dict["_dns.resolver.arpa"] = 12;
        var span = new DnsParsingSpan(dict, buffer);
        data.WriteTo(ref span);

        // RDLENGTH (2) + priority (2) + first label length. Compression would be 0xC0.
        Assert.Equal(4, buffer[4]);
        Assert.Equal((byte)'_', buffer[5]);
    }

    [Fact]
    public void MessageRoundTripKeepsSvcbType()
    {
        var record = new DomainResourceRecord(
            new DomainLabels("_dns.resolver.arpa"),
            DomainRecordType.SVCB,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(300),
            new SvcbData(1, new DomainLabels("dns.example.com"), [SvcbParameter.Alpn("h2")]));
        var request = DomainMessage.CreateRequest("_dns.resolver.arpa", DomainRecordType.SVCB);
        var message = DomainMessage.CreateResponse(request, [record], responseCode: DomainResponseCode.NoError);

        var buffer = new byte[message.EstimatedSize];
        var written = DomainMessageEncoder.Encode(buffer, message);
        var decoded = DomainMessageEncoder.Decode(buffer.AsSpan(0, written));

        var svcb = Assert.IsType<SvcbData>(decoded.Records.Answers[0].Data);
        Assert.Equal("dns.example.com", svcb.TargetName.ToString());
        Assert.Equal(DomainRecordType.SVCB, decoded.Records.Answers[0].Type);
    }

    private static SvcbData RoundTrip(SvcbData data)
    {
        var buffer = new byte[512];
        using var dict = DictionaryPool<string, int>.Default.Get();
        var span = new DnsParsingSpan(dict, buffer);
        data.WriteTo(ref span);
        var written = span.Offset;
        var read = new ReadOnlyDnsParsingSpan(buffer.AsSpan(0, written));
        var rdlength = DomainMessageEncoder.ReadUnsignedShortAndAdvance(ref read);
        return Assert.IsType<SvcbData>(SvcbData.ReadFrom(ref read, rdlength));
    }
}
