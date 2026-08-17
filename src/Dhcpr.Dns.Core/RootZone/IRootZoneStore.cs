using Dhcpr.Dns.Core.Protocol.Zone;

namespace Dhcpr.Dns.Core.RootZone;

public interface IRootZoneStore
{
    /// <summary>Current non-expired snapshot, or null if unavailable.</summary>
    RootZoneSnapshot? Current { get; }

    /// <summary>Current snapshot even if expired, or null if never loaded.</summary>
    RootZoneSnapshot? CurrentIgnoringExpiry { get; }

    void Set(RootZoneSnapshot? snapshot);
}
