using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Protocol.Zone;

namespace Dhcpr.Dns.Core.UnitTests;

public class ZoneFileParserTests
{
    [Fact]
    public void ParseRootZone_ReadsSoaNsGlueAndDs()
    {
        var text = File.ReadAllText(FixturePath("root-zone-excerpt.txt"));
        var loadedAt = new DateTimeOffset(2026, 7, 26, 12, 0, 0, TimeSpan.Zero);

        var snapshot = ZoneFileParser.ParseRootZone(text, loadedAt);

        Assert.Equal(loadedAt, snapshot.LoadedAt);
        Assert.Equal(1800, (int)snapshot.Soa.RefreshInterval.TotalSeconds);
        Assert.Equal(900, (int)snapshot.Soa.RetryInterval.TotalSeconds);
        Assert.Equal(604800, (int)snapshot.Soa.ExpireInterval.TotalSeconds);
        Assert.True(snapshot.TryGetRecords("com", out var com));
        Assert.Contains(com, r => r.Type == DomainRecordType.NS);
        Assert.Contains(com, r => r.Type == DomainRecordType.DS);
        Assert.True(snapshot.TryGetRecords("a.gtld-servers.net", out var glue));
        Assert.Contains(glue, r =>
            r.Type == DomainRecordType.A &&
            ((IPAddressData)r.Data).Address.Equals(IPAddress.Parse("192.5.6.30")));
        Assert.True(snapshot.TryGetRecords("", out var apex));
        Assert.Contains(apex, r => r.Type == DomainRecordType.SOA);
    }

    [Fact]
    public void ParseRootZone_SupportsParenthesesAndOrigin()
    {
        const string text = """
            $ORIGIN example.
            $TTL 3600
            @ 3600 IN SOA ns.example. hostmaster.example. (
                1
                7200
                3600
                1209600
                3600 )
            @ IN NS ns.example.
            ns IN A 192.0.2.1
            """;

        var snapshot = ZoneFileParser.ParseRootZone(text);

        Assert.Equal(7200, (int)snapshot.Soa.RefreshInterval.TotalSeconds);
        Assert.True(snapshot.TryGetRecords("example", out var apex));
        Assert.Contains(apex, r => r.Type == DomainRecordType.NS);
        Assert.True(snapshot.TryGetRecords("ns.example", out var ns));
        Assert.Contains(ns, r => r.Type == DomainRecordType.A);
    }

    [Fact]
    public void ParseNamedRootAddresses_ExtractsAAndAaaa()
    {
        const string text = """
            ; comment
            .                        3600000      NS    A.ROOT-SERVERS.NET.
            A.ROOT-SERVERS.NET.      3600000      A     198.41.0.4
            A.ROOT-SERVERS.NET.      3600000      AAAA  2001:503:ba3e::2:30
            """;

        var addresses = ZoneFileParser.ParseNamedRootAddresses(text);

        Assert.Contains(IPAddress.Parse("198.41.0.4"), addresses);
        Assert.Contains(IPAddress.Parse("2001:503:ba3e::2:30"), addresses);
    }

    [Fact]
    public void Parse_ReadsBindStyleMxTxtCnameSrvAndTtlUnits()
    {
        var text = File.ReadAllText(FixturePath("bind-style-zone.txt"));

        var records = ZoneFileParser.Parse(text);

        Assert.Contains(records, r => r.Type == DomainRecordType.MX && r.Name.ToString() == "example.com");
        Assert.Contains(records, r =>
            r.Type == DomainRecordType.TXT &&
            r.Name.ToString() == "txt.example.com" &&
            ((TextData)r.Data).Text == "hello world");
        Assert.Contains(records, r =>
            r.Type == DomainRecordType.CNAME &&
            r.Name.ToString() == "www.example.com");
        Assert.Contains(records, r =>
            r.Type == DomainRecordType.SRV &&
            r.Name.ToString() == "_sip._tcp.example.com" &&
            ((ServiceData)r.Data).Port == 5060);
        Assert.Equal(TimeSpan.FromHours(1), records.First(r => r.Type == DomainRecordType.SOA).TimeToLive);
    }

    [Fact]
    public void ParseRootZone_SkipsDnssecAndGenerateLines()
    {
        var text = File.ReadAllText(FixturePath("root-zone-with-dnssec.txt"));

        var snapshot = ZoneFileParser.ParseRootZone(text);

        Assert.Equal(1800, (int)snapshot.Soa.RefreshInterval.TotalSeconds);
        Assert.True(snapshot.TryGetRecords("com", out var com));
        Assert.Contains(com, r => r.Type == DomainRecordType.NS);
        Assert.Contains(com, r => r.Type == DomainRecordType.DS);
        Assert.DoesNotContain(com, r => r.Type is DomainRecordType.RRSIG or DomainRecordType.DNSKEY or DomainRecordType.NSEC);
        Assert.True(snapshot.TryGetRecords("a.gtld-servers.net", out var glue));
        Assert.Contains(glue, r => r.Type == DomainRecordType.A);
        Assert.False(snapshot.TryGetRecords("host1.example", out _));
    }

    private static string FixturePath(string name)
        => Path.Combine(AppContext.BaseDirectory, "Fixtures", name);
}
