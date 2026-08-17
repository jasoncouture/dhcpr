using Dhcpr.Dns.Core.Protocol.Zone;

namespace Dhcpr.Dns.Core.Authoritative;

public interface IAuthoritativeZoneStore
{
    /// <summary>
    /// Replaces the published zone set. The first zone wins when two share an apex.
    /// </summary>
    void Publish(IReadOnlyList<AuthoritativeZone> zones);

    /// <summary>
    /// Returns the longest enclosing published zone for <paramref name="qname"/>, or <see langword="null"/>.
    /// </summary>
    AuthoritativeZone? FindZone(string qname);

    /// <summary>
    /// Returns the published zone whose apex is exactly <paramref name="apex"/>, or <see langword="null"/>.
    /// </summary>
    AuthoritativeZone? FindZoneExactApex(string apex);
}
