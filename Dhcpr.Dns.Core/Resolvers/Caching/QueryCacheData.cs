using DNS.Protocol;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

public sealed record class QueryCacheData(IResponse Response, DateTimeOffset Created, TimeSpan TimeToLive)
{
    public QueryCacheData(IResponse response, TimeSpan timeToLive) : this(response, DateTimeOffset.Now, timeToLive) { }
}