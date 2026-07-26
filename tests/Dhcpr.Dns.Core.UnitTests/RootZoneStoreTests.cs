using Dhcpr.Dns.Core.Protocol.Zone;
using Dhcpr.Dns.Core.RootZone;

namespace Dhcpr.Dns.Core.UnitTests;

public class RootZoneStoreTests
{
    [Fact]
    public void Current_NullWhenExpired()
    {
        var text = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "root-zone-excerpt.txt"));
        var snapshot = ZoneFileParser.ParseRootZone(text, DateTimeOffset.UtcNow - TimeSpan.FromDays(30));
        var store = new RootZoneStore();
        store.Set(snapshot);

        Assert.Null(store.Current);
        Assert.NotNull(store.CurrentIgnoringExpiry);
    }

    [Fact]
    public void Current_ReturnsLiveSnapshot()
    {
        var text = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "root-zone-excerpt.txt"));
        var snapshot = ZoneFileParser.ParseRootZone(text, DateTimeOffset.UtcNow);
        var store = new RootZoneStore();
        store.Set(snapshot);

        Assert.Same(snapshot, store.Current);
    }

    [Fact]
    public void ExpiresAt_UsesFileLoadedAtPlusSoaExpire()
    {
        var text = File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "root-zone-excerpt.txt"));
        var loadedAt = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var snapshot = ZoneFileParser.ParseRootZone(text, loadedAt);

        Assert.Equal(loadedAt + TimeSpan.FromSeconds(604800), snapshot.ExpiresAt);
    }
}
