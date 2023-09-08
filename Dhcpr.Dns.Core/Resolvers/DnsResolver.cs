using System.Diagnostics;

using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Resolvers.Caching;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Abstractions;

using DNS.Protocol;
using DNS.Protocol.ResourceRecords;

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

    private static readonly RecordType[] RecordTypes = { RecordType.A, RecordType.AAAA };

    public async Task<IResponse> Resolve(IRequest request, CancellationToken cancellationToken)
    {
        var response = await InnerResolver(request, cancellationToken).ConfigureAwait(false);
        if (response is null)
        {
            response = Response.FromRequest(request);
            response.ResponseCode = ResponseCode.ServerFailure;
            return response;
        }

        if (response.Id != request.Id)
        {
            _logger.LogWarning("Request ID was {requestId}, but we tried to respond with ID {responseId}, fixing it", request.Id, response.Id);
            response = new Response(response);
            response.Id = request.Id;
        }

        if (request.Questions[0].Type is RecordType.CNAME or RecordType.A or RecordType.AAAA &&
            response.AnswerRecords.Any(i => i.Type == RecordType.CNAME) &&
            !response.AnswerRecords.Any(i => i.Type is RecordType.A or RecordType.AAAA))
        {
            _logger.LogInformation("Canonical name did not provide addresses, and recursion is requested. Looking up A and AAAA records for the target.");
            response = new Response(response);
            using var cnames = response.AnswerRecords.OfType<CanonicalNameResourceRecord>().ToPooledList();
            foreach (var recordType in RecordTypes)
            {
                foreach (var cname in cnames)
                {
                    _logger.LogInformation("Resolving canonical name: {recordType}:{cname}", recordType, cname.CanonicalDomainName);

                    var innerRequest = new Request()
                    {
                        Questions = { new Question(new Domain(cname.CanonicalDomainName.ToString())) }
                    };
                    var innerResponse = await InnerResolver(innerRequest, cancellationToken).ConfigureAwait(false);
                    if (innerResponse is null)
                    {
                        response = Response.FromRequest(request);
                        response.ResponseCode = ResponseCode.ServerFailure;
                        return response;
                    }

                    foreach (var answer in innerResponse.AnswerRecords.OfType<IPAddressResourceRecord>().Where(i => i.Type == recordType))
                    {
                        response.AnswerRecords.Add(answer);
                    }
                }
            }
        }
        return response;
    }
    public async Task<IResponse?> InnerResolver(IRequest request,
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