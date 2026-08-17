using Dhcpr.Dns.Core.Protocol.Zone;

namespace Dhcpr.Dns.Core.RootZone;

public interface IRootZoneStore
{
    /// <summary>Current non-expired snapshot, or null if unavailable.</summary>
    RootZoneSnapshot? Current { get; }

    /// <summary>Current snapshot even if expired, or null if never loaded.</summary>
    RootZoneSnapshot? CurrentIgnoringExpiry { get; }

    /// <summary>
    /// Replaces the stored snapshot. <paramref name="snapshot"/> may be <see langword="null"/> to clear.
    /// </summary>
    void Set(RootZoneSnapshot? snapshot);
}
