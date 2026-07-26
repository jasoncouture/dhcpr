namespace Dhcpr.Dns.Core.Protocol.Processing;

// Terminal fallback: unhandled query → SERVFAIL, never NXDOMAIN.
public sealed class ServerFailureDomainMiddleware : IDomainMessageMiddleware
{
    public ValueTask<DomainMessage?> ProcessAsync(DomainMessageContext context, CancellationToken cancellationToken)
    {
        return ValueTask.FromResult<DomainMessage?>(DomainMessage.CreateResponse(
            context.DomainMessage,
            DomainResourceRecords.Empty,
            DomainResponseCode.ServerFailure));
    }

    public string Name { get; } = "Server Failure Fallback";
    public int Priority { get; } = int.MaxValue;
}
