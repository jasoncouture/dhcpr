using Dhcpr.Dns.Core.Protocol.Zone;

namespace Dhcpr.Dns.Core.RootZone;

public sealed class RootZoneStore : IRootZoneStore
{
    private RootZoneSnapshot? _snapshot;

    public RootZoneSnapshot? Current
    {
        get
        {
            var snapshot = Volatile.Read(ref _snapshot);
            if (snapshot is null)
                return null;
            return snapshot.IsExpired(DateTimeOffset.UtcNow) ? null : snapshot;
        }
    }

    public void Set(RootZoneSnapshot? snapshot)
        => Volatile.Write(ref _snapshot, snapshot);

    public RootZoneSnapshot? CurrentIgnoringExpiry
        => Volatile.Read(ref _snapshot);
}
