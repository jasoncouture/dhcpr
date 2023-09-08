using DNS.Client.RequestResolver;
using DNS.Protocol;

using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

public class CachedResolver : ICachedResolver
{
    private readonly IRequestResolver _innerResolver;
    private readonly IDnsCache _dnsCache;
    private readonly ILogger<CachedResolver> _logger;

    public CachedResolver(IRequestResolver innerResolver, IDnsCache dnsCache, ILogger<CachedResolver> logger)
    {
        _innerResolver = innerResolver;
        _dnsCache = dnsCache;
        _logger = logger;
    }
    public async Task<IResponse> Resolve(IRequest request, CancellationToken cancellationToken = new CancellationToken())
    {
        if (_dnsCache.TryGetCachedResponse(request, out var result))
        {
            _logger.LogInformation("DNS Questions answered by cache: {status}",
                result.ResponseCode);
            return result;
        }

        result = await _innerResolver.Resolve(request, cancellationToken).ConfigureAwait(false);
        _dnsCache.TryAddCacheEntry(request, result);
        return result;
    }
}