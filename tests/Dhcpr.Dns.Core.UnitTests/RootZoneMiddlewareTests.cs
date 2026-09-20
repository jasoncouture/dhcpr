using System.Collections.Immutable;
using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Protocol.Zone;
using Dhcpr.Dns.Core.RootZone;

using Microsoft.Extensions.Options;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class RootZoneMiddlewareTests
{
    [Fact]
    public async Task MissWhenStoreEmpty()
    {
        var middleware = CreateMiddleware(store: new RootZoneStore(), dnssecEnabled: false);
        var result = await middleware.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("com", DomainRecordType.NS)),
            CancellationToken.None);

        Assert.Equal(DomainResponseCode.ServerFailure, result.Flags.ResponseCode);
    }

    [Fact]
    public async Task MissCallsInner()
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var request = DomainMessage.CreateRequest("com", DomainRecordType.NS);
        var passed = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(passed);

        var middleware = CreateMiddleware(new RootZoneStore(), dnssecEnabled: false, inner);
        var result = await middleware.ProcessAsync(
            new DomainMessageContext(null, null, request),
            CancellationToken.None);

        Assert.Same(passed, result);
        await inner.Received(1)
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task HitReturnsNsAndGlue_WhenDnssecDisabled()
    {
        var text = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "Fixtures", "root-zone-excerpt.txt"));
        var snapshot = ZoneFileParser.ParseRootZone(text, DateTimeOffset.UtcNow);
        var store = new RootZoneStore();
        store.Set(snapshot);

        var middleware = CreateMiddleware(store, dnssecEnabled: false);
        var result = await middleware.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("com", DomainRecordType.NS)),
            CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NoError, result!.Flags.ResponseCode);
        Assert.Contains(result.Records.Answers, r => r.Type == DomainRecordType.NS);
        Assert.Contains(result.Records.Additional, r =>
            r.Type == DomainRecordType.A &&
            ((IPAddressData)r.Data).Address.Equals(IPAddress.Parse("192.5.6.30")));
    }

    [Fact]
    public async Task UnsignedSnapshotMissesWhenDnssecEnabled()
    {
        var text = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "Fixtures", "root-zone-excerpt.txt"));
        var store = new RootZoneStore();
        store.Set(ZoneFileParser.ParseRootZone(text, DateTimeOffset.UtcNow));

        var middleware = CreateMiddleware(store, dnssecEnabled: true);
        var result = await middleware.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("com", DomainRecordType.NS)),
            CancellationToken.None);

        Assert.Equal(DomainResponseCode.ServerFailure, result.Flags.ResponseCode);
    }

    [Fact]
    public async Task IncludesCoveringRrsigWhenPresent()
    {
        var owner = new DomainLabels("com");
        var ns = new DomainResourceRecord(
            owner,
            DomainRecordType.NS,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(172800),
            new NameData(new DomainLabels("a.gtld-servers.net")));
        var rrsig = new DomainResourceRecord(
            owner,
            DomainRecordType.RRSIG,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(172800),
            new ResourceRecordSignatureData(
                DomainRecordType.NS,
                DnssecAlgorithmType.EcdsaP256Sha256,
                1,
                172800,
                (uint)DateTimeOffset.UtcNow.AddDays(1).ToUnixTimeSeconds(),
                (uint)DateTimeOffset.UtcNow.AddDays(-1).ToUnixTimeSeconds(),
                1234,
                DomainLabels.Empty,
                ImmutableArray.Create<byte>(1, 2, 3, 4)));

        var soa = new StartOfAuthorityData(
            new DomainLabels("a.root-servers.net"),
            new DomainLabels("nstld.verisign-grs.com"),
            1,
            TimeSpan.FromSeconds(1800),
            TimeSpan.FromSeconds(900),
            TimeSpan.FromDays(7),
            TimeSpan.FromDays(1));
        var snapshot = new RootZoneSnapshot(
            soa,
            TimeSpan.FromDays(1),
            DateTimeOffset.UtcNow,
            new Dictionary<string, ImmutableArray<DomainResourceRecord>>
            {
                ["com"] = [ns, rrsig]
            });
        var store = new RootZoneStore();
        store.Set(snapshot);

        var middleware = CreateMiddleware(store, dnssecEnabled: true);
        var result = await middleware.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("com", DomainRecordType.NS)),
            CancellationToken.None);

        Assert.NotNull(result);
        Assert.Contains(result!.Records.Answers, r => r.Type == DomainRecordType.NS);
        Assert.Contains(result.Records.Answers, r => r.Type == DomainRecordType.RRSIG);
    }

    [Fact]
    public async Task ExpiredCoveringRrsigMissesWhenDnssecEnabled()
    {
        var owner = new DomainLabels("com");
        var ns = new DomainResourceRecord(
            owner,
            DomainRecordType.NS,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(172800),
            new NameData(new DomainLabels("a.gtld-servers.net")));
        var rrsig = new DomainResourceRecord(
            owner,
            DomainRecordType.RRSIG,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(172800),
            new ResourceRecordSignatureData(
                DomainRecordType.NS,
                DnssecAlgorithmType.EcdsaP256Sha256,
                1,
                172800,
                (uint)DateTimeOffset.UtcNow.AddDays(-1).ToUnixTimeSeconds(),
                (uint)DateTimeOffset.UtcNow.AddDays(-7).ToUnixTimeSeconds(),
                1234,
                DomainLabels.Empty,
                ImmutableArray.Create<byte>(1, 2, 3, 4)));

        var soa = new StartOfAuthorityData(
            new DomainLabels("a.root-servers.net"),
            new DomainLabels("nstld.verisign-grs.com"),
            1,
            TimeSpan.FromSeconds(1800),
            TimeSpan.FromSeconds(900),
            TimeSpan.FromDays(7),
            TimeSpan.FromDays(1));
        var snapshot = new RootZoneSnapshot(
            soa,
            TimeSpan.FromDays(1),
            DateTimeOffset.UtcNow,
            new Dictionary<string, ImmutableArray<DomainResourceRecord>>
            {
                ["com"] = [ns, rrsig]
            });
        var store = new RootZoneStore();
        store.Set(snapshot);

        var middleware = CreateMiddleware(store, dnssecEnabled: true);
        var result = await middleware.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("com", DomainRecordType.NS)),
            CancellationToken.None);

        Assert.Equal(DomainResponseCode.ServerFailure, result.Flags.ResponseCode);
    }

    [Fact]
    public async Task ExpiredSnapshotIsMiss()
    {
        var text = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "Fixtures", "root-zone-excerpt.txt"));
        var snapshot = ZoneFileParser.ParseRootZone(
            text,
            DateTimeOffset.UtcNow - TimeSpan.FromDays(30));
        var store = new RootZoneStore();
        store.Set(snapshot);

        var middleware = CreateMiddleware(store, dnssecEnabled: false);
        var result = await middleware.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("com", DomainRecordType.NS)),
            CancellationToken.None);

        Assert.Equal(DomainResponseCode.ServerFailure, result.Flags.ResponseCode);
    }

    [Fact]
    public async Task DirectedUpstreamUsesSnapshotWhenDnssecDisabled()
    {
        var text = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "Fixtures", "root-zone-excerpt.txt"));
        var store = new RootZoneStore();
        store.Set(ZoneFileParser.ParseRootZone(text, DateTimeOffset.UtcNow));

        var middleware = CreateMiddleware(store, dnssecEnabled: false);
        var context = new DomainMessageContext(null, null, DomainMessage.CreateRequest("com", DomainRecordType.NS))
        {
            UpstreamEndpoints = [new IPEndPoint(IPAddress.Parse("198.41.0.4"), 53)]
        };

        var result = await middleware.ProcessAsync(context, CancellationToken.None);
        Assert.NotNull(result);
        Assert.Contains(result!.Records.Answers, r => r.Type == DomainRecordType.NS);
    }

    [Fact]
    public async Task DirectedUpstreamUsesSignedSnapshotWhenDnssecEnabled()
    {
        var owner = new DomainLabels("com");
        var ns = new DomainResourceRecord(
            owner,
            DomainRecordType.NS,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(172800),
            new NameData(new DomainLabels("a.gtld-servers.net")));
        var rrsig = new DomainResourceRecord(
            owner,
            DomainRecordType.RRSIG,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(172800),
            new ResourceRecordSignatureData(
                DomainRecordType.NS,
                DnssecAlgorithmType.EcdsaP256Sha256,
                1,
                172800,
                (uint)DateTimeOffset.UtcNow.AddDays(1).ToUnixTimeSeconds(),
                (uint)DateTimeOffset.UtcNow.AddDays(-1).ToUnixTimeSeconds(),
                1234,
                DomainLabels.Empty,
                ImmutableArray.Create<byte>(1, 2, 3, 4)));

        var soa = new StartOfAuthorityData(
            new DomainLabels("a.root-servers.net"),
            new DomainLabels("nstld.verisign-grs.com"),
            1,
            TimeSpan.FromSeconds(1800),
            TimeSpan.FromSeconds(900),
            TimeSpan.FromDays(7),
            TimeSpan.FromDays(1));
        var snapshot = new RootZoneSnapshot(
            soa,
            TimeSpan.FromDays(1),
            DateTimeOffset.UtcNow,
            new Dictionary<string, ImmutableArray<DomainResourceRecord>>
            {
                ["com"] = [ns, rrsig]
            });
        var store = new RootZoneStore();
        store.Set(snapshot);

        var middleware = CreateMiddleware(store, dnssecEnabled: true);
        var context = new DomainMessageContext(null, null, DomainMessage.CreateRequest("com", DomainRecordType.NS))
        {
            UpstreamEndpoints = [new IPEndPoint(IPAddress.Parse("198.41.0.4"), 53)]
        };

        var result = await middleware.ProcessAsync(context, CancellationToken.None);
        Assert.NotNull(result);
        Assert.Contains(result!.Records.Answers, r => r.Type == DomainRecordType.NS);
        Assert.Contains(result.Records.Answers, r => r.Type == DomainRecordType.RRSIG);
    }

    [Fact]
    public async Task DsQueryReturnsDsRecords_WhenDnssecDisabled()
    {
        var text = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "Fixtures", "root-zone-excerpt.txt"));
        var store = new RootZoneStore();
        store.Set(ZoneFileParser.ParseRootZone(text, DateTimeOffset.UtcNow));

        var middleware = CreateMiddleware(store, dnssecEnabled: false);
        var result = await middleware.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("com", DomainRecordType.DS)),
            CancellationToken.None);

        Assert.NotNull(result);
        Assert.All(result!.Records.Answers, r => Assert.Equal(DomainRecordType.DS, r.Type));
    }

    private static RootZoneMiddleware CreateMiddleware(
        IRootZoneStore store,
        bool dnssecEnabled,
        IDomainMessageMiddleware? inner = null)
    {
        if (inner is null)
        {
            inner = Substitute.For<IDomainMessageMiddleware>();
            inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
                .Returns(call => DomainMessage.CreateResponse(
                call.Arg<DomainMessageContext>().DomainMessage,
                DomainResourceRecords.Empty,
                DomainResponseCode.ServerFailure));
        }

        return new(
            inner,
            store,
            Monitor(new DnsConfiguration
            {
                Dnssec = new DnssecConfiguration { Enabled = dnssecEnabled }
            }));
    }

    private static IOptionsMonitor<T> Monitor<T>(T value)
    {
        var monitor = Substitute.For<IOptionsMonitor<T>>();
        monitor.CurrentValue.Returns(value);
        monitor.Get(Arg.Any<string?>()).Returns(value);
        return monitor;
    }
}
