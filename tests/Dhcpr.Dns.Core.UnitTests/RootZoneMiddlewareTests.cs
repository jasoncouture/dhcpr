using System.Collections.Immutable;
using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Protocol.Zone;
using Dhcpr.Dns.Core.RootZone;

namespace Dhcpr.Dns.Core.UnitTests;

public class RootZoneMiddlewareTests
{
    [Fact]
    public async Task MissWhenStoreEmpty()
    {
        var store = new RootZoneStore();
        var middleware = new RootZoneMiddleware(store);
        var result = await middleware.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("com", DomainRecordType.NS)),
            CancellationToken.None);

        Assert.Null(result);
    }

    [Fact]
    public async Task HitReturnsNsAndGlue()
    {
        var text = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "Fixtures", "root-zone-excerpt.txt"));
        var snapshot = ZoneFileParser.ParseRootZone(text, DateTimeOffset.UtcNow);
        var store = new RootZoneStore();
        store.Set(snapshot);

        var middleware = new RootZoneMiddleware(store);
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
    public async Task ExpiredSnapshotIsMiss()
    {
        var text = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "Fixtures", "root-zone-excerpt.txt"));
        // Expire interval in fixture is 604800s; load far in the past.
        var snapshot = ZoneFileParser.ParseRootZone(
            text,
            DateTimeOffset.UtcNow - TimeSpan.FromDays(30));
        var store = new RootZoneStore();
        store.Set(snapshot);

        var middleware = new RootZoneMiddleware(store);
        var result = await middleware.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("com", DomainRecordType.NS)),
            CancellationToken.None);

        Assert.Null(result);
    }

    [Fact]
    public async Task DsQueryReturnsDsRecords()
    {
        var text = await File.ReadAllTextAsync(Path.Combine(AppContext.BaseDirectory, "Fixtures", "root-zone-excerpt.txt"));
        var store = new RootZoneStore();
        store.Set(ZoneFileParser.ParseRootZone(text, DateTimeOffset.UtcNow));

        var middleware = new RootZoneMiddleware(store);
        var result = await middleware.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("com", DomainRecordType.DS)),
            CancellationToken.None);

        Assert.NotNull(result);
        Assert.All(result!.Records.Answers, r => Assert.Equal(DomainRecordType.DS, r.Type));
    }
}
