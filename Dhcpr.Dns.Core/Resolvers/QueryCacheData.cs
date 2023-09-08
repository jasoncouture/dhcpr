using DNS.Protocol;

namespace Dhcpr.Dns.Core.Resolvers;

public record class QueryCacheData(IResponse Response, DateTimeOffset Created)
{
    public QueryCacheData(IResponse response) : this(response, DateTimeOffset.Now) { }
}