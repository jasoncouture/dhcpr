using Dhcpr.Dns.Core.Resolvers.Caching;

using DNS.Protocol;

namespace Dhcpr.Dns.Core;

public interface IDnsMemoryCacheWriter
{
    void AddToMemoryCache(QueryCacheKey key, IResponse? response, TimeSpan timeToLive);
}