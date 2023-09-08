using Dhcpr.Core.Queue;

namespace Dhcpr.Dns.Core;

public sealed class DnsCacheMessageProcessor : IQueueMessageProcessor<DnsCacheMessage>
{
    private readonly IDnsDatabaseCache _dnsDatabaseCache;

    public DnsCacheMessageProcessor(IDnsDatabaseCache dnsDatabaseCache)
    {
        _dnsDatabaseCache = dnsDatabaseCache;
    }

    public async Task ProcessMessageAsync(DnsCacheMessage message, CancellationToken cancellationToken)
    {
        var (key, response, timeToLive, invalidate) = message;
        if (invalidate)
        {
            // TODO: Delete cache entry from DB and memory cache
            return;
        }
        // TODO: Add cache record to DB, and to local cache
        return;
    }
}