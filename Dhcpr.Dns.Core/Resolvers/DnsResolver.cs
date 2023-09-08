using System.Diagnostics;

using DNS.Protocol;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Resolvers;

public sealed class DnsResolver : IDnsResolver, IDisposable
{
    private readonly IRootResolver _rootResolver;
    private readonly IDnsCache _dnsCache;
    private readonly IForwardResolver _forwardResolver;
    private readonly ILogger<DnsResolver> _logger;
    private long _useParallelResolver;
    private readonly IDisposable? _configChangeSubscription;
    private readonly Func<IRequest, CancellationToken, Task<IResponse?>> _parallelMethod;
    private readonly Func<IRequest, CancellationToken, Task<IResponse?>> _sequentalMethod;

    private Func<IRequest, CancellationToken, Task<IResponse?>> SelectedMethod =>
        UseParallelResolver ? _parallelMethod : _sequentalMethod;

    public DnsResolver(
        IOptionsMonitor<DnsConfiguration> configuration,
        IParallelDnsResolver parallelDnsResolver,
        ISequentialDnsResolver sequentialDnsResolver,
        IRootResolver rootResolver,
        IDnsCache dnsCache,
        IForwardResolver forwardResolver,
        ILogger<DnsResolver> logger
    )
    {
        _rootResolver = rootResolver;
        _dnsCache = dnsCache;
        _forwardResolver = forwardResolver;
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
        _logger.LogDebug("Configuration changed applied");
    }

    public async Task<IResponse?> Resolve(IRequest request,
        CancellationToken cancellationToken = new CancellationToken())
    {
        if (request.Questions.Count is > 1 or 0)
        {
            _logger.LogWarning(
                "Rejecting request with NotImplemented, this server only supports a single question per request, but this request has {count} questions",
                request.Questions.Count
            );
            var response = Response.FromRequest(request);
            response.ResponseCode = ResponseCode.NotImplemented;
            return response;
        }

        _logger.LogInformation("Query: {query}", request.Questions[0]);

        var start = Stopwatch.GetTimestamp();
        try
        {
            if (_dnsCache.TryGetCachedResponse(request, out var result))
            {
                _logger.LogInformation("DNS Questions answered by cache: {status}",
                    result.ResponseCode);
                return result;
            }

            result = await SelectedMethod(request, cancellationToken).ConfigureAwait(false);
            if (result is not null and not { ResponseCode: ResponseCode.NameError })
            {
                _logger.LogInformation("DNS Questions answered by internal resolver: {status}",
                    result.ResponseCode);
                _dnsCache.TryAddCacheEntry(request, result);
                return result;
            }

            result = await _forwardResolver.Resolve(request, cancellationToken).ConfigureAwait(false);
            if (result is not null and not { ResponseCode: ResponseCode.NameError })
            {
                _logger.LogInformation("DNS Questions answered by forward resolver: {status}", result.ResponseCode);
                _dnsCache.TryAddCacheEntry(request, result);
                return result;
            }

            result = await _rootResolver.Resolve(request, cancellationToken).ConfigureAwait(false);
            if (result is not null)
            {
                _logger.LogInformation("DNS Questions answered by recursive root resolver: {status}",
                    result.ResponseCode);
                _dnsCache.TryAddCacheEntry(request, result);
            }

            return result;
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Unhandled exception, returning SRVFAIL to client");
            var response = Response.FromRequest(request);
            response.ResponseCode = ResponseCode.ServerFailure;
            return response;
        }
        finally
        {
            _logger.LogDebug("Resolve() completed in {timeTaken}ms", Stopwatch.GetElapsedTime(start).TotalMilliseconds);
        }
    }


    public void Dispose()
    {
        _configChangeSubscription?.Dispose();
    }
}