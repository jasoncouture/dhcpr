using Dhcpr.Dns.Core.Resolvers.Caching;

using DNS.Protocol;

namespace Dhcpr.Dns.Core;

public interface IDnsDatabaseCache
{
    public ValueTask<IResponse?> TryGetCachedResponse(QueryCacheKey key, CancellationToken cancellationToken);

    void QueueCacheRecord(QueryCacheKey key, IResponse response, TimeSpan timeToLive,
        CancellationToken cancellationToken);

    void InvalidateCacheRecord(QueryCacheKey request, CancellationToken cancellationToken);
}