using DNS.Client.RequestResolver;
using DNS.Protocol;

using Microsoft.Extensions.DependencyInjection;

namespace Dhcpr.Dns.Core.Resolvers;

public sealed class ScopedResolverWrapper<T> : IScopedResolverWrapper<T> where T : IRequestResolver
{
    private readonly IServiceProvider _serviceProvider;

    public ScopedResolverWrapper(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }

    public async Task<IResponse> Resolve(IRequest request,
        CancellationToken cancellationToken = new CancellationToken())
    {
        await using var scope = _serviceProvider.CreateAsyncScope();
        var resolver = scope.ServiceProvider.GetRequiredService<T>();
        return await resolver.Resolve(request, cancellationToken);
    }
}