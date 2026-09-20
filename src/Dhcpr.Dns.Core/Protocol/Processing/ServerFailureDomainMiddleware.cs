namespace Dhcpr.Dns.Core.Protocol.Processing;

// Terminal fallback: unhandled query → SERVFAIL, never NXDOMAIN.
public sealed class ServerFailureDomainMiddleware : IDomainMessageMiddleware
{
    public async ValueTask<DomainMessage?> ProcessAsync(DomainMessageContext context, CancellationToken cancellationToken)
    {
        await Task.Yield();
        context.ServFailReason = $"no handler answered ({Name})";
        context.AnsweredBy ??= Name;
        return DomainMessage.CreateResponse(
            context.DomainMessage,
            DomainResourceRecords.Empty,
            DomainResponseCode.ServerFailure);
    }

    public string Name { get; } = "Server Failure Fallback";
    public int Priority { get; } = int.MaxValue;
}
