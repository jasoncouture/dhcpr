namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// Rejects QTYPEs outside the known <see cref="DomainRecordType"/> set (e.g. ANY/255)
/// with SERVFAIL before cache or upstream work. Attack traffic must not poison the cache.
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
            if (!Enum.IsDefined(question.Type))
            {
                context.ServFailReason = $"unsupported query type {(ushort)question.Type}";
                return DomainMessage.CreateResponse(
                    context.DomainMessage,
                    DomainResourceRecords.Empty,
                    DomainResponseCode.ServerFailure);
            }
        }

        return await _inner.ProcessAsync(context, cancellationToken);
    }
}
