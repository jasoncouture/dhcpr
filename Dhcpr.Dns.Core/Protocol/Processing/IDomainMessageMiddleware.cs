namespace Dhcpr.Dns.Core.Protocol.Processing;

public interface IDomainMessageMiddleware
{
    public ValueTask<DomainMessage?> ProcessAsync(DomainMessageContext context, CancellationToken cancellationToken);
    string Name { get; }
    int Priority { get; }
}