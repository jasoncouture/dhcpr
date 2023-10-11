using Dhcpr.Dns.Core.Protocol;

using DnsZone;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Files;

public interface IBindFileZoneProvider
{
    DnsZoneFile? GetZoneOrNull(DomainLabels labels);
}