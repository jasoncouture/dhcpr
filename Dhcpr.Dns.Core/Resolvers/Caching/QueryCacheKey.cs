using DNS.Protocol;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

public sealed record QueryCacheKey(string Domain, RecordType Type, RecordClass Class)
{
    public QueryCacheKey(IMessageEntry question)
        : this(
            question.Name.ToString()!.ToLowerInvariant(),
            question.Type,
            question.Class
        )
    {
    }
}