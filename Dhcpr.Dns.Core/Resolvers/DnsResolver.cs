using System.Diagnostics;

using Dhcpr.Core;
using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Resolvers.Caching;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Abstractions;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Database;

using DNS.Client.RequestResolver;
using DNS.Protocol;
using DNS.Protocol.ResourceRecords;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Resolvers;

public interface IScopedResolverWrapper<T> : IRequestResolver where T : IRequestResolver
{
    
}
public sealed class ScopedResolverWrapper<T> : IScopedResolverWrapper<T> where T : IRequestResolver
{
    private readonly IServiceProvider _serviceProvider;

    public ScopedResolverWrapper(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }

    public async Task<IResponse> Resolve(IRequest request, CancellationToken cancellationToken = new CancellationToken())
    {
        await using var scope = _serviceProvider.CreateAsyncScope();
        var resolver = scope.ServiceProvider.GetRequiredService<T>();
        return await resolver.Resolve(request, cancellationToken).ConfigureAwait(false);
    }
}
public sealed class DnsResolver : IDnsResolver, IDisposable
{
    private readonly IDatabaseResolver _databaseResolver;
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
        IDatabaseResolver databaseResolver,
        IParallelDnsResolver parallelDnsResolver,
        ISequentialDnsResolver sequentialDnsResolver,
        IRootResolver rootResolver,
        IDnsCache dnsCache,
        IForwardResolver forwardResolver,
        ILogger<DnsResolver> logger
    )
    {
        _databaseResolver = databaseResolver;
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

        if (response.Id != request.Id)
        {
            _logger.LogWarning("Request ID was {requestId}, but we tried to respond with ID {responseId}, fixing it",
                request.Id, response.Id);
            response = new Response(response);
            response.Id = request.Id;
        }

        if (request.Questions[0].Type is RecordType.CNAME or RecordType.A or RecordType.AAAA &&
            response.AnswerRecords.Any(i => i.Type == RecordType.CNAME) &&
            !response.AnswerRecords.Any(i => i.Type is RecordType.A or RecordType.AAAA))
        {
            _logger.LogInformation(
                "Canonical name did not provide addresses, and recursion is requested. Looking up A and AAAA records for the target.");
            response = new Response(response);
            using var cnames = response.AnswerRecords.OfType<CanonicalNameResourceRecord>().ToPooledList();
            foreach (var recordType in RecordTypes)
            {
                foreach (var cname in cnames)
                {
                    _logger.LogInformation("Resolving canonical name: {recordType}:{cname}", recordType,
                        cname.CanonicalDomainName);

                    var innerRequest = new Request()
                    {
                        Questions = { new Question(new Domain(cname.CanonicalDomainName.ToString())) }
                    };
                    var innerResponse = await InnerResolver(innerRequest, cancellationToken).ConfigureAwait(false);

                    foreach (var answer in innerResponse.AnswerRecords.OfType<IPAddressResourceRecord>()
                                 .Where(i => i.Type == recordType))
                    {
                        response.AnswerRecords.Add(answer);
                    }
                }
            }
        }

        response = new Response(response);
        OrderResourceRecords(response);

        return response;
    }

    private void OrderResourceRecords(IResponse response)
    {
        OrderResourceRecords(response.AnswerRecords);
        OrderResourceRecords(response.AdditionalRecords);
        OrderResourceRecords(response.AuthorityRecords);
    }

    // This function will shuffle IP records,  
    private void OrderResourceRecords(IList<IResourceRecord> records)
    {
        // No point in wasting time here, there's no addresses to shuffle.
        using var ipRecords = records.OfType<IPAddressResourceRecord>().ToPooledList();
        if (ipRecords.Count < 2) return;
        using var otherRecords = records.Where(i => i is not IPAddressResourceRecord)
            .ToPooledList();
        records.Clear();
        foreach (
            var addressRecord in ipRecords
                .OrderBy(i => i.IPAddress.IsInLocalSubnet() ? 0 : 1)
                .ThenShuffle()
        )
            records.Add(addressRecord);

        foreach (
            var otherRecord in otherRecords
        )
            records.Add(otherRecord);
    }

    public async Task<IResponse> InnerResolver(IRequest request,
        CancellationToken cancellationToken = new CancellationToken())
    {
        if (request.Questions.Count == 0)
        {
            var response = Response.FromRequest(request);
            response.ResponseCode = ResponseCode.FormatError;
            return response;
        }

        if (request.Questions.Count > 1)
        {
            var questions = request.Questions;
            var innerResolveTasks = new List<Task<IResponse>>();
            foreach (var question in questions)
            {
                var nextRequest = new Request(request);
                nextRequest.Id = Random.Shared.Next(0, int.MaxValue);
                nextRequest.Questions.Clear();
                nextRequest.Questions.Add(question);
                innerResolveTasks.Add(InnerResolver(nextRequest, cancellationToken));
            }

            var allResponses = await Task.WhenAll(innerResolveTasks).ConfigureAwait(false);
            var response = Response.FromRequest(request);
            response.ResponseCode = allResponses.Select(i => i.ResponseCode).Max();

            foreach (var innerResponse in allResponses)
            {
                foreach (var record in innerResponse.AnswerRecords)
                    response.AnswerRecords.Add(record);
                foreach (var record in innerResponse.AuthorityRecords)
                    response.AuthorityRecords.Add(record);
                foreach (var record in innerResponse.AdditionalRecords)
                    response.AdditionalRecords.Add(record);
            }

            return response;
        }

        _logger.LogInformation("Query: {query}", request.Questions[0]);

        var start = Stopwatch.GetTimestamp();
        try
        {
            var result = await _dnsCache.TryGetCachedResponseAsync(request, cancellationToken).ConfigureAwait(false);
            if (result is not null)
            {
                _logger.LogInformation("DNS Questions answered by cache: {status}",
                    result.ResponseCode);
                return result;
            }

            using var tokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

            var otherResolverTask = SelectedMethod(new Request(request) { Id = Random.Shared.Next(0, int.MaxValue) },
                tokenSource.Token).OperationCancelledToNull();

            var rootResolverTask = _rootResolver
                .Resolve(new Request(request) { Id = Random.Shared.Next(0, int.MaxValue) }, tokenSource.Token)
                .OperationCancelledToNull().ConvertExceptionsToNull();

            var dbResolverTask = _databaseResolver.Resolve(
                new Request(request) { Id = Random.Shared.Next(0, int.MaxValue) }, tokenSource.Token
            ).OperationCancelledToNull();


            var forwardResolverTask = _forwardResolver
                .Resolve(new Request(request) { Id = Random.Shared.Next(0, int.MaxValue) }, tokenSource.Token)
                .OperationCancelledToNull();

            var response = await dbResolverTask.ConfigureAwait(false);
            if (response is not null)
            {
                tokenSource.Cancel();
                return response;
            }

            response = await otherResolverTask.ConfigureAwait(false);
            if (response is { ResponseCode: ResponseCode.NoError })
            {
                tokenSource.Cancel();
                await _dnsCache.TryAddCacheEntryAsync(request, response, cancellationToken).ConfigureAwait(false);
                return response;
            }

            response = await forwardResolverTask.ConfigureAwait(false);
            if (response is { ResponseCode: ResponseCode.NoError })
            {
                tokenSource.Cancel();
                await _dnsCache.TryAddCacheEntryAsync(request, response, cancellationToken).ConfigureAwait(false);
                return response;
            }

            response = await rootResolverTask.ConfigureAwait(false);
            if (response is not null)
            {
                tokenSource.Cancel();
                await _dnsCache.TryAddCacheEntryAsync(request, response, cancellationToken).ConfigureAwait(false);
                return response;
            }

            var nxdomain = Response.FromRequest(request);
            nxdomain.ResponseCode = ResponseCode.NameError;
            return nxdomain;
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