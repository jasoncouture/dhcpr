using Dhcpr.Dns.Core.Protocol;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

public readonly record struct DnsCacheKey(string Name, DomainRecordType Type, DomainRecordClass Class)
{
    public static DnsCacheKey FromQuestion(DomainQuestion question)
        => new(question.Name.ToString().ToLowerInvariant(), question.Type, question.Class);
}
