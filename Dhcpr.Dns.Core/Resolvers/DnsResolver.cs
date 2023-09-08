using System.Diagnostics;

using Dhcpr.Core;
using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Resolvers.Caching;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Abstractions;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Database;

using DNS.Protocol;
using DNS.Protocol.ResourceRecords;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Resolvers;

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
                foreach(var record in innerResponse.AnswerRecords)
                    response.AnswerRecords.Add(record);
                foreach(var record in innerResponse.AuthorityRecords)
                    response.AuthorityRecords.Add(record);
                foreach(var record in innerResponse.AdditionalRecords)
                    response.AdditionalRecords.Add(record);
            }

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

            using var tokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var tasks = new List<Task<IResponse?>>();
            tasks.Add(_databaseResolver.Resolve(new Request(request) { Id = Random.Shared.Next(0, int.MaxValue)}, tokenSource.Token).OperationCancelledToNull());
            tasks.Add(SelectedMethod(new Request(request) { Id = Random.Shared.Next(0, int.MaxValue)}, tokenSource.Token).OperationCancelledToNull());
            tasks.Add(_forwardResolver.Resolve(new Request(request) { Id = Random.Shared.Next(0, int.MaxValue)}, tokenSource.Token).OperationCancelledToNull());
            tasks.Add(_rootResolver.Resolve(new Request(request) { Id = Random.Shared.Next(0, int.MaxValue)}, tokenSource.Token).OperationCancelledToNull().ConvertExceptionsToNull());

            for (var x = 0; x < tasks.Count; x++)
            {
                _logger.LogDebug("Waiting for DNS Resolver task {index}", x);
                var nextResponse = await tasks[x].ConfigureAwait(false);
                _logger.LogDebug("DNS resolver task returned {response}", nextResponse);
                if (nextResponse is null)
                    continue;
                nextResponse = new Response(nextResponse) { Id = request.Id };
                if (x == 0) 
                    return nextResponse;

                if (nextResponse.ResponseCode != ResponseCode.NoError)
                    continue;

                tokenSource.Cancel();
                _dnsCache.TryAddCacheEntry(request, nextResponse);
                try
                {
                    await Task.WhenAll(tasks).ConfigureAwait(false);
                }
                catch
                {
                    // ignored.
                }

                return nextResponse;
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