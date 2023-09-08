using DNS.Protocol;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Resolvers;

public sealed class DnsResolver : IDnsResolver, IDisposable
{
    private readonly IRootResolver _rootResolver;
    private readonly IDnsCache _dnsCache;
    private readonly ILogger<DnsResolver> _logger;
    private long _useParallelResolver;
    private readonly IDisposable? _configChangeSubscription;
    private readonly Func<IRequest, CancellationToken, Task<IResponse?>> _parallelMethod;
    private readonly Func<IRequest, CancellationToken, Task<IResponse?>> _sequentalMethod;

    private Func<IRequest, CancellationToken, Task<IResponse?>> SelectedMethod =>
        UseParallelResolver ? _parallelMethod : _sequentalMethod;

    public DnsResolver(IOptionsMonitor<DnsConfiguration> configuration, IParallelDnsResolver parallelDnsResolver,
        ISequentialDnsResolver sequentialDnsResolver, IRootResolver rootResolver, IDnsCache dnsCache, ILogger<DnsResolver> logger)
    {
        _rootResolver = rootResolver;
        _dnsCache = dnsCache;
        _logger = logger;
        _configChangeSubscription = configuration.OnChange(OnConfigurationChanged);
        _parallelMethod = parallelDnsResolver.Resolve;
        _sequentalMethod = sequentialDnsResolver.Resolve;
        OnConfigurationChanged(configuration.CurrentValue);
    }

    private bool UseParallelResolver => _useParallelResolver == 1;

    private void OnConfigurationChanged(DnsConfiguration configuration)
    {
        Interlocked.Exchange(ref _useParallelResolver, configuration.UseParallelResolver ? 1 : 0);
    }

    public async Task<IResponse?> Resolve(IRequest request,
        CancellationToken cancellationToken = new CancellationToken())
    {
        if (_dnsCache.TryGetCachedResponse(request, out var result))
        {
            _logger.LogDebug("Cache hit for query {request}, response: {response}", request, result);
            return result;
        }
        result = await SelectedMethod(request, cancellationToken).ConfigureAwait(false);
        if (result is not null and not { ResponseCode: ResponseCode.NameError })
        {
            _dnsCache.TryAddCacheEntry(request, result);
            return result;
        }

        result = await _rootResolver.Resolve(request, cancellationToken).ConfigureAwait(false);
        if (result is not null)
        {
            _dnsCache.TryAddCacheEntry(request, result);
        }

        return result;
    }


    public void Dispose()
    {
        _configChangeSubscription?.Dispose();
    }
}