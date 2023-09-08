using DNS.Protocol;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

public interface IDnsCache
{
    IResponse? TryGetCachedResponse(IRequest request);
    void TryAddCacheEntry(IRequest request, IResponse? response);
}