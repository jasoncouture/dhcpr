namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// Rejects query class other than IN/CH with NOTIMP, QTYPE ANY and unknown
/// types with NOTIMP, and HINFO / AXFR / IXFR with REFUSED.
/// </summary>
public sealed class UnsupportedQueryTypeMiddleware : IDomainMessageMiddleware
{
    private readonly IDomainMessageMiddleware _inner;

    public UnsupportedQueryTypeMiddleware(IDomainMessageMiddleware inner)
    {
        _inner = inner;
    }

    public string Name => _inner.Name;
    public int Priority => _inner.Priority;

    public async ValueTask<DomainMessage?> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        foreach (var question in context.DomainMessage.Questions)
        {
            if (question.Class is not DomainRecordClass.IN and not DomainRecordClass.CH)
            {
                context.AnsweredBy = "query-class";
                return DomainMessage.CreateResponse(
                    context.DomainMessage,
                    DomainResourceRecords.Empty,
                    DomainResponseCode.NotImplemented);
            }

            if (RefuseCode(question.Type) is { } rcode)
            {
                context.AnsweredBy = "UnsupportedQueryType";
                return DomainMessage.CreateResponse(
                    context.DomainMessage,
                    DomainResourceRecords.Empty,
                    rcode);
            }
        }

        return await _inner.ProcessAsync(context, cancellationToken);
    }

    internal static DomainResponseCode? RefuseCode(DomainRecordType type)
        => type switch
        {
            DomainRecordType.HINFO or DomainRecordType.AXFR or DomainRecordType.IXFR
                => DomainResponseCode.Refused,
            DomainRecordType.ANY => DomainResponseCode.NotImplemented,
            _ when !Enum.IsDefined(type) => DomainResponseCode.NotImplemented,
            _ => null
        };
}
