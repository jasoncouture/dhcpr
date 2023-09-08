using DNS.Protocol;

namespace Dhcpr.Dns.Core;

public record struct QueryCacheKey(string Domain, RecordType Type, RecordClass Class, OperationCode OperationCode)
{
    public QueryCacheKey(IRequest request, IMessageEntry question) : this(question.Name.ToString()!, question.Type,
        question.Class, request.OperationCode)
    {
    }
}