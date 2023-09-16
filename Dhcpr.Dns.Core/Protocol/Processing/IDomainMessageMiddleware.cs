namespace Dhcpr.Dns.Core.Protocol.Processing;

public interface IDomainMessageMiddleware
{
    public ValueTask<DomainMessage?> ProcessAsync(DomainMessageContext context, CancellationToken cancellationToken);
    string Name { get; }
    int Priority { get; }
}

public class NameErrorDomainMiddleware : IDomainMessageMiddleware
{
    public ValueTask<DomainMessage?> ProcessAsync(DomainMessageContext context, CancellationToken cancellationToken)
    {
        return ValueTask.FromResult<DomainMessage?>(DomainMessage.CreateResponse(context.DomainMessage));
    }

    public string Name { get; } = "Name Error Middleware";
    public int Priority { get; } = int.MaxValue;
}