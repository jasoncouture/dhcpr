namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// Rejects QTYPE ANY (255) and other unknown QTYPEs with NOTIMP before cache or
/// upstream work. Attack traffic must not poison the cache.
/// </summary>
public sealed class UnsupportedQueryTypeMiddleware : IDomainMessageMiddleware
{
    // RFC 1035 / 8482: * / ANY
    private const DomainRecordType AnyQueryType = (DomainRecordType)255;

    private readonly IDomainMessageMiddleware _inner;

    public UnsupportedQueryTypeMiddleware(IDomainMessageMiddleware inner)
    {
        _inner = inner;
    }

    public string Name => _inner.Name;
    public int Priority => _inner.Priority;

    public ValueTask<DomainMessage?> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        foreach (var question in context.DomainMessage.Questions)
        {
            if (question.Type == AnyQueryType || !Enum.IsDefined(question.Type))
            {
                context.AnsweredBy = "UnsupportedQueryType";
                return ValueTask.FromResult<DomainMessage?>(DomainMessage.CreateResponse(
                    context.DomainMessage,
                    DomainResourceRecords.Empty,
                    DomainResponseCode.NotImplemented));
            }
        }

        // Pass through the inner ValueTask — do not async/await; this runs on every query.
        return _inner.ProcessAsync(context, cancellationToken);
    }
}
