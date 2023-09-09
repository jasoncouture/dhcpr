using System.Diagnostics;

using Dhcpr.Core;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Abstractions;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Database;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;
using Dhcpr.Dns.Core.Resolvers.Resolvers.SystemResolver;

using DNS.Protocol;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Resolvers;

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