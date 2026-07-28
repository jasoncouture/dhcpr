using System.Net;

using Dhcpr.Dns.Core.Authoritative;
using Dhcpr.Dns.Core.DynamicDns;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Protocol.Zone;

namespace Dhcpr.Dns.Core.UnitTests;

public class DynamicDnsTests
{
    private const string FooBarZone = """
        $ORIGIN foo.bar.
        $TTL 3600
        @ IN SOA ns.foo.bar. hostmaster.foo.bar. ( 1 7200 3600 1209600 3600 )
        @ IN NS ns.foo.bar.
        ns IN A 192.0.2.1
        www IN A 192.0.2.10
        """;

    [Fact]
    public void Update_Badauth_WhenCredentialsWrong()
    {
        using var harness = CreateHarness();
        var body = DynDnsUpdateProcessor.Process(
            harness.Store,
            harness.Zones,
            harness.Config,
            DynDnsUpdateProcessor.BasicAuthorization("user", "wrong"),
            "host.foo.bar",
            "203.0.113.10",
            remoteIp: null,
            forwardedForFirstHop: null);

        Assert.Equal("badauth", body);
    }

    [Fact]
    public void Update_Badauth_WhenAuthMissing()
    {
        using var harness = CreateHarness();
        var body = DynDnsUpdateProcessor.Process(
            harness.Store,
            harness.Zones,
            harness.Config,
            authorizationHeader: null,
            "host.foo.bar",
            "203.0.113.10",
            remoteIp: null,
            forwardedForFirstHop: null);

        Assert.Equal("badauth", body);
    }

    [Fact]
    public void Update_Nohost_WhenOutsideLoadedZone()
    {
        using var harness = CreateHarness();
        var body = Update(harness, "host.other.example", "203.0.113.10");
        Assert.Equal("nohost", body);
    }

    [Fact]
    public void Update_Notfqdn_WhenHostnameEmpty()
    {
        using var harness = CreateHarness();
        var body = DynDnsUpdateProcessor.Process(
            harness.Store,
            harness.Zones,
            harness.Config,
            DynDnsUpdateProcessor.BasicAuthorization(harness.Config.Username, harness.Config.Password),
            hostnameParam: "  ",
            myipParam: "203.0.113.10",
            remoteIp: null,
            forwardedForFirstHop: null);

        Assert.Equal("notfqdn", body);
    }

    [Fact]
    public void Update_GoodThenNochg()
    {
        using var harness = CreateHarness();
        Assert.Equal("good 203.0.113.10", Update(harness, "host.foo.bar", "203.0.113.10"));
        Assert.Equal("nochg 203.0.113.10", Update(harness, "host.foo.bar", "203.0.113.10"));
    }

    [Fact]
    public void Update_MultiHost_OneLinePerHost()
    {
        using var harness = CreateHarness();
        var body = Update(harness, "a.foo.bar,b.foo.bar", "203.0.113.20");
        Assert.Equal("good 203.0.113.20\ngood 203.0.113.20", body);
    }

    [Fact]
    public void Update_Ipv6AndBothFamilies()
    {
        using var harness = CreateHarness();
        Assert.Equal(
            "good 2001:db8::1",
            Update(harness, "v6.foo.bar", "2001:db8::1"));
        Assert.Equal(
            "good 203.0.113.30,2001:db8::2",
            Update(harness, "both.foo.bar", "203.0.113.30,2001:db8::2"));

        Assert.True(harness.Store.TryGet("v6.foo.bar", out var v6));
        Assert.Null(v6.Ipv4);
        Assert.Equal("2001:db8::1", v6.Ipv6);

        Assert.True(harness.Store.TryGet("both.foo.bar", out var both));
        Assert.Equal("203.0.113.30", both.Ipv4);
        Assert.Equal("2001:db8::2", both.Ipv6);
    }

    [Fact]
    public void Update_LeavesOtherFamilyWhenOnlyOneSent()
    {
        using var harness = CreateHarness();
        Update(harness, "host.foo.bar", "203.0.113.1,2001:db8::1");
        Update(harness, "host.foo.bar", "203.0.113.2");

        Assert.True(harness.Store.TryGet("host.foo.bar", out var entry));
        Assert.Equal("203.0.113.2", entry.Ipv4);
        Assert.Equal("2001:db8::1", entry.Ipv6);
    }

    [Fact]
    public void Persist_RoundTripsAcrossStores()
    {
        using var harness = CreateHarness();
        Update(harness, "host.foo.bar", "203.0.113.40");

        var reloaded = DynamicDnsTestHelpers.CreateStore(harness.DataPath, harness.Config);
        reloaded.LoadFromDisk();

        Assert.True(reloaded.TryGet("host.foo.bar", out var entry));
        Assert.Equal("203.0.113.40", entry.Ipv4);
    }

    [Fact]
    public async Task Middleware_ServesOverlayAa_DoNotCache()
    {
        using var harness = CreateHarness();
        Update(harness, "dyn.foo.bar", "203.0.113.50");

        var middleware = new DynamicDnsMiddleware(harness.Store, harness.Zones);
        var request = DomainMessage.CreateRequest("dyn.foo.bar");
        var context = new DomainMessageContext(null, null, request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.True(context.DoNotCacheResponse);
        Assert.True(result!.Flags.Authoritative);
        Assert.Contains(result.Records.Answers, r =>
            r.Type == DomainRecordType.A &&
            ((IPAddressData)r.Data).Address.Equals(IPAddress.Parse("203.0.113.50")));
    }

    [Fact]
    public async Task Middleware_OverlayWinsOverZoneFileRr()
    {
        using var harness = CreateHarness();
        Update(harness, "www.foo.bar", "203.0.113.60");

        var middleware = new DynamicDnsMiddleware(harness.Store, harness.Zones);
        var request = DomainMessage.CreateRequest("www.foo.bar");
        var context = new DomainMessageContext(null, null, request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Contains(result!.Records.Answers, r =>
            r.Type == DomainRecordType.A &&
            ((IPAddressData)r.Data).Address.Equals(IPAddress.Parse("203.0.113.60")));
        Assert.DoesNotContain(result.Records.Answers, r =>
            r.Type == DomainRecordType.A &&
            ((IPAddressData)r.Data).Address.Equals(IPAddress.Parse("192.0.2.10")));
    }

    [Fact]
    public async Task Overlay_SurvivesZoneCatalogRepublish()
    {
        using var harness = CreateHarness();
        Update(harness, "dyn.foo.bar", "203.0.113.70");

        harness.Zones.Publish([BuildZone(FooBarZone, "foo.bar.bind")]);

        var middleware = new DynamicDnsMiddleware(harness.Store, harness.Zones);
        var request = DomainMessage.CreateRequest("dyn.foo.bar");
        var context = new DomainMessageContext(null, null, request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Contains(result!.Records.Answers, r =>
            r.Type == DomainRecordType.A &&
            ((IPAddressData)r.Data).Address.Equals(IPAddress.Parse("203.0.113.70")));
    }

    private static string Update(Harness harness, string hostname, string myip)
        => DynDnsUpdateProcessor.Process(
            harness.Store,
            harness.Zones,
            harness.Config,
            DynDnsUpdateProcessor.BasicAuthorization(harness.Config.Username, harness.Config.Password),
            hostname,
            myip,
            remoteIp: null,
            forwardedForFirstHop: null);

    private static Harness CreateHarness()
    {
        var dataPath = Path.Combine(Path.GetTempPath(), "dhcpr-dyndns-" + Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(dataPath);
        var config = new DynamicDnsConfiguration
        {
            Enabled = true,
            Username = "user",
            Password = "pass",
            TtlSeconds = 60
        };
        var store = DynamicDnsTestHelpers.CreateStore(dataPath, config);
        var zones = new AuthoritativeZoneStore();
        zones.Publish([BuildZone(FooBarZone, "foo.bar.bind")]);
        return new Harness(dataPath, store, zones, config);
    }

    private static AuthoritativeZone BuildZone(string text, string path)
    {
        var records = ZoneFileParser.Parse(text);
        return AuthoritativeZoneBuilder.FromRecords(records, path);
    }

    private sealed class Harness : IDisposable
    {
        public Harness(string dataPath, DynamicDnsStore store, AuthoritativeZoneStore zones, DynamicDnsConfiguration config)
        {
            DataPath = dataPath;
            Store = store;
            Zones = zones;
            Config = config;
        }

        public string DataPath { get; }
        public DynamicDnsStore Store { get; }
        public AuthoritativeZoneStore Zones { get; }
        public DynamicDnsConfiguration Config { get; }

        public void Dispose()
        {
            try
            {
                if (Directory.Exists(DataPath))
                    Directory.Delete(DataPath, recursive: true);
            }
            catch
            {
                // best-effort cleanup
            }
        }
    }
}
