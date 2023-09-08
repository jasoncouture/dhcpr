using Dhcpr.Core.Queue;
using Dhcpr.Dns.Core.Resolvers.Caching;

using DNS.Protocol;

namespace Dhcpr.Dns.Core;

public class DnsDatabaseCache : IDnsDatabaseCache
{
    private readonly IMessageQueue<DnsCacheMessage> _cacheMessageQueue;

    public DnsDatabaseCache(IMessageQueue<DnsCacheMessage> cacheMessageQueue)
    {
        _cacheMessageQueue = cacheMessageQueue;
    }

    public ValueTask<IResponse?> TryGetCachedResponse(QueryCacheKey key, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public void QueueCacheRecord(QueryCacheKey key, IResponse response, TimeSpan timeToLive,
        CancellationToken cancellationToken)
    {
        var cacheMessage = new DnsCacheMessage(key, response, timeToLive, false);
        _cacheMessageQueue.Enqueue(cacheMessage, cancellationToken);
    }

    public void InvalidateCacheRecord(QueryCacheKey request, CancellationToken cancellationToken)
    {
        var cacheMessage = new DnsCacheMessage(request, null, TimeSpan.Zero, true);
        _cacheMessageQueue.Enqueue(cacheMessage, cancellationToken);
    }
}