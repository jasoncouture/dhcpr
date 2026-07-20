namespace Dhcpr.Dns.Core.Protocol.Processing;

public interface IDomainMessageMiddleware
{
    public ValueTask<DomainMessage?> ProcessAsync(DomainMessageContext context, CancellationToken cancellationToken);
    string Name => GetType().Name;
    int Priority => 0;
}