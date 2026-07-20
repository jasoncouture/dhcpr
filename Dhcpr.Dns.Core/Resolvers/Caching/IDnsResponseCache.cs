using Dhcpr.Dns.Core.Protocol;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

public interface IDnsResponseCache
{
    bool TryGet(DomainMessage request, out DomainMessage? response);
    void Set(DomainMessage request, DomainMessage response);
}
