namespace Dhcpr.Dns.Core.Protocol.Processing;

public interface IDomainMessageMiddleware
{
    public ValueTask<DomainMessage?> ProcessAsync(DomainMessageContext context, CancellationToken cancellationToken);
    string GroupName { get; }
    int Priority { get; }
}

public class NameErrorDomainMiddleware : IDomainMessageMiddleware
{
    public ValueTask<DomainMessage?> ProcessAsync(DomainMessageContext context, CancellationToken cancellationToken)
    {
        return ValueTask.FromResult<DomainMessage?>(DomainMessage.CreateResponse(context.DomainMessage));
    }

    public string GroupName { get; } = "NameError";
    public int Priority { get; } = 0;
}