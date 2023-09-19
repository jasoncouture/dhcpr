using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

public sealed class CacheResolverDecorator : IDomainMessageMiddleware
{
    private readonly IDomainMessageMiddleware _innerMiddleware;

    public CacheResolverDecorator(IDomainMessageMiddleware innerMiddleware)
    {
        _innerMiddleware = innerMiddleware;
    }

    public async ValueTask<DomainMessage?> ProcessAsync(DomainMessageContext context, CancellationToken cancellationToken)
    {
        return await _innerMiddleware.ProcessAsync(context, cancellationToken);
    }

    public string Name => _innerMiddleware.Name;

    public int Priority => _innerMiddleware.Priority;
}