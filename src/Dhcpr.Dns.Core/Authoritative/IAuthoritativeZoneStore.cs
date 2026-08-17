using Dhcpr.Dns.Core.Protocol.Zone;

namespace Dhcpr.Dns.Core.Authoritative;

public interface IAuthoritativeZoneStore
{
    void Publish(IReadOnlyList<AuthoritativeZone> zones);
    AuthoritativeZone? FindZone(string qname);
    AuthoritativeZone? FindZoneExactApex(string apex);
}
