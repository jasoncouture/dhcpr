using System.Diagnostics;

using Dhcpr.Core;
using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Resolvers.Caching;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Abstractions;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Database;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;
using Dhcpr.Dns.Core.Resolvers.Resolvers.SystemResolver;

using DNS.Client.RequestResolver;
using DNS.Protocol;
using DNS.Protocol.ResourceRecords;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Resolvers;

public sealed class DnsOutputFilter : IDnsOutputFilter
{
    public async Task<IResponse> UpdateResponse(IRequestResolver resolver, IRequest request, IResponse? response,
        CancellationToken cancellationToken)
    {
        if (response is null)
        {
            response = Response.FromRequest(request);
            response.ResponseCode = ResponseCode.ServerFailure;
            return response;
        }

        using var records = response.ToResourceRecordPooledList();


        // Some servers use shortened names, and when we return it directly, it confuses clients.
        // So doing a deep clone re-creates those records without the shortened names.
        response = response.Clone(deep: true);

        if (request.RecursionDesired &&
            request.Questions[0].Type is RecordType.CNAME or RecordType.A or RecordType.AAAA &&
            response.AnswerRecords.Any(i => i.Type == RecordType.CNAME) &&
            !response.AnswerRecords.Any(i => i.Type is RecordType.A or RecordType.AAAA))
        {
            response = new Response(response);
            var nameStack = new Stack<CanonicalNameResourceRecord>();
            using var canonicalNames = response.AnswerRecords.OfType<CanonicalNameResourceRecord>().ToPooledList();
            foreach (var cname in canonicalNames)
            {
                nameStack.Push(cname);
            }

            var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            while (nameStack.TryPop(out var cname))
            {
                if (!visited.Add(cname.Name.ToString()!))
                    continue;
                foreach (var question in new[]
                         {
                             new Question(new Domain(cname.CanonicalDomainName.ToString()),
                                 request.Questions[0].Type, RecordClass.ANY)
                         })
                {
                    var innerRequest = new Request() { RecursionDesired = true, Questions = { question } };

                    var innerResponse = await resolver.Resolve(innerRequest, cancellationToken);
                    using var innerRecords = innerResponse.ToResourceRecordPooledList();
                    foreach (
                        var innerCanonicalNameResourceRecord in innerResponse.AnswerRecords
                            .OfType<CanonicalNameResourceRecord>()
                    )
                    {
                        nameStack.Push(innerCanonicalNameResourceRecord);
                        response.AnswerRecords.Add(innerCanonicalNameResourceRecord);
                    }

                    foreach (var answer in innerResponse.AnswerRecords.OfType<IPAddressResourceRecord>())
                    {
                        response.AnswerRecords.Add(answer);
                    }
                }
            }
        }

        using var secondPassRecords = response.ToResourceRecordPooledList();
        if (request.RecursionDesired &&
            secondPassRecords.All(i => i.Type != request.Questions[0].Type && i.Type != RecordType.CNAME))
        {
            response = Response.FromRequest(request);
            response.ResponseCode = ResponseCode.NameError;
            return response;
        }

        using var allAddressRecords = response.AnswerRecords.OfType<IPAddressResourceRecord>().ToPooledList();
        using var deduplicatedIpAddressResourceRecords = response.AnswerRecords.OfType<IPAddressResourceRecord>()
            .DistinctBy(i => (i.IPAddress, i.Name, i.Type)).ToPooledList();
        if (allAddressRecords.Count != deduplicatedIpAddressResourceRecords.Count)
        {
            foreach (var address in allAddressRecords)
                response.AnswerRecords.Remove(address);

            foreach (var address in deduplicatedIpAddressResourceRecords)
                response.AnswerRecords.Add(address);
        }


        OrderResourceRecords(response);

        if (response.Id != request.Id)
            response.Id = request.Id;

        return response;
    }

    private static void OrderResourceRecords(IResponse response)
    {
        OrderResourceRecords(response.AnswerRecords);
        OrderResourceRecords(response.AdditionalRecords);
        OrderResourceRecords(response.AuthorityRecords);
    }

    // This function will shuffle IP records,  
    private static void OrderResourceRecords(IList<IResourceRecord> records)
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
            records.Add(addressRecord.Clone());

        foreach (
            var otherRecord in otherRecords
        )
            records.Add(otherRecord);
    }
}

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

    public async Task<IResponse> Resolve(IRequest request,
        CancellationToken cancellationToken = new CancellationToken())
    {
        await using var scope = _serviceProvider.CreateAsyncScope();
        var resolver = scope.ServiceProvider.GetRequiredService<T>();
        return await resolver.Resolve(request, cancellationToken);
    }
}

public sealed class DnsResolver : IDnsResolver, IDisposable
{
    private readonly IDatabaseResolver _databaseResolver;
    private readonly IRootResolver _rootResolver;
    private readonly IForwardResolver _forwardResolver;
    private readonly ILogger<DnsResolver> _logger;
    private readonly ISystemNameResolver _systemNameResolver;
    private readonly IDisposable? _configChangeSubscription;

    public DnsResolver(
        IOptionsMonitor<DnsConfiguration> configuration,
        IDatabaseResolver databaseResolver,
        IRootResolver rootResolver,
        IForwardResolver forwardResolver,
        ILogger<DnsResolver> logger,
        ISystemNameResolver systemNameResolver
    )
    {
        _databaseResolver = databaseResolver;
        _rootResolver = rootResolver;
        _forwardResolver = forwardResolver;
        _logger = logger;
        _systemNameResolver = systemNameResolver;
        _configChangeSubscription = configuration.OnChange(OnConfigurationChanged);
    }

    private void OnConfigurationChanged(DnsConfiguration configuration)
    {
    }

    public async Task<IResponse> Resolve(IRequest request, CancellationToken cancellationToken)
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
                var nextRequest = new Request(request) { Id = Random.Shared.Next(0, int.MaxValue) };
                nextRequest.Questions.Clear();
                nextRequest.Questions.Add(question);
                innerResolveTasks.Add(Resolve(nextRequest, cancellationToken));
            }

            var allResponses = await Task.WhenAll(innerResolveTasks);
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
            using var tokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            var response = await _systemNameResolver.Resolve(request, tokenSource.Token);
            if (response is not null)
                return response;
            // var dbResolverTask = _databaseResolver.Resolve(
            //     new Request(request) { Id = Random.Shared.Next(0, int.MaxValue) }, tokenSource.Token
            // ).OperationCancelledToNull();

            var rootResolverTask = _rootResolver
                .Resolve(new Request(request) { Id = Random.Shared.Next(0, int.MaxValue) }, tokenSource.Token)
                .OperationCancelledToNull().ConvertExceptionsToNull();


            var forwardResolverTask = _forwardResolver
                .Resolve(new Request(request) { Id = Random.Shared.Next(0, int.MaxValue) }, tokenSource.Token)
                .OperationCancelledToNull();

            // response = await dbResolverTask;
            // if (response is not null)
            // {
            //     tokenSource.Cancel();
            //     return response;
            // }

            response = await forwardResolverTask;
            if (response is { ResponseCode: ResponseCode.NoError })
            {
                tokenSource.Cancel();
                return response;
            }

            response = await rootResolverTask;
            if (response is not null)
            {
                tokenSource.Cancel();
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