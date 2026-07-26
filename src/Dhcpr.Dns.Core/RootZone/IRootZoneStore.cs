using Dhcpr.Dns.Core.Protocol.Zone;

namespace Dhcpr.Dns.Core.RootZone;

public interface IRootZoneStore
{
    /// <summary>Current non-expired snapshot, or null if unavailable.</summary>
    RootZoneSnapshot? Current { get; }
}
