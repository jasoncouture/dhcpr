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
        var result = await _dnsCache.TryGetCachedResponseAsync(request, cancellationToken).ConfigureAwait(false);
        if (result is not null)
        {
            _logger.LogInformation("DNS Questions answered by cache: {status}",
                result.ResponseCode);
            return result;
        }

        result = await _innerResolver.Resolve(request, cancellationToken).ConfigureAwait(false);
        await _dnsCache.TryAddCacheEntryAsync(request, result).ConfigureAwait(false);
        return result;
    }
}