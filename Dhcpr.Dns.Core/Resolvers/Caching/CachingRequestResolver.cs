using DNS.Client.RequestResolver;
using DNS.Protocol;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

public sealed class CachingRequestResolver : IRequestResolver
{
    private readonly IRequestResolver _requestResolverImplementation;
    private readonly IDnsCache _dnsCache;

    public CachingRequestResolver(IRequestResolver requestResolverImplementation, IDnsCache dnsCache)
    {
        _requestResolverImplementation = requestResolverImplementation;
        _dnsCache = dnsCache;
    }

    public async Task<IResponse?> Resolve(IRequest request, CancellationToken cancellationToken = new CancellationToken())
    {
        var response = _dnsCache.TryGetCachedResponse(request);
        if (response is not null)
            return response;
        response = await _requestResolverImplementation.Resolve(request, cancellationToken);
        _dnsCache.TryAddCacheEntry(request, response);
        return response;
    }
}