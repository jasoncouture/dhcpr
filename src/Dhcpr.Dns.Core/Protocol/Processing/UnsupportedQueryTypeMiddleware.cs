namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// Rejects QTYPE ANY (255) and other unknown QTYPEs with NOTIMP before cache or
/// upstream work. Attack traffic must not poison the cache.
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
            if (question.Type is DomainRecordType.ANY || !Enum.IsDefined(question.Type))
            {
                context.AnsweredBy = "UnsupportedQueryType";
                return DomainMessage.CreateResponse(
                    context.DomainMessage,
                    DomainResourceRecords.Empty,
                    DomainResponseCode.NotImplemented);
            }
        }

        return await _inner.ProcessAsync(context, cancellationToken);
    }
}
