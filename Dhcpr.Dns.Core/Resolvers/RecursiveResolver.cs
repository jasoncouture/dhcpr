using System.Diagnostics;
using System.Net;

using DNS.Client;
using DNS.Client.RequestResolver;
using DNS.Protocol;
using DNS.Protocol.ResourceRecords;

using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core;

public sealed class RecursiveResolver : MultiResolver, IRecursiveResolver
{
    private readonly IResolverCache _resolverCache;
    private readonly ILogger<RecursiveResolver> _logger;
    private readonly IEnumerable<IPEndPoint> _servers;

    public RecursiveResolver(IEnumerable<IPEndPoint> servers, IResolverCache resolverCache,
        ILogger<RecursiveResolver> logger)
    {
        _servers = servers;
        _resolverCache = resolverCache;
        _logger = logger;
        AddResolvers(servers.Select(i => _resolverCache.GetResolver(i, CreateUdpResolver)).Cast<IRequestResolver>()
            .ToArray());
        _logger.LogDebug("Recursive resolver created for {server}", servers);
    }

    public override async Task<IResponse?> Resolve(IRequest request,
        CancellationToken cancellationToken = new CancellationToken())
    {
        using var pooledAnswers = ListPool<IResourceRecord>.Default.Get();
        using var pooledAuthorityRecords = ListPool<IResourceRecord>.Default.Get();
        using var pooledAdditionalAnswerRecords = ListPool<IResourceRecord>.Default.Get();

        foreach (var question in request.Questions)
        {
            var lookupName = question.Name.ToString()!;

            using var lookupNameParts = lookupName.Split('.').Reverse().ToPooledList();
            _logger.LogDebug("Starting recursive lookup for {name}, starting with initial server {server}", lookupName,
                _servers);
            var innerResolver =
                _resolverCache.GetMultiResolver<ParallelResolver, UdpRequestResolver>(_servers, CreateParallelResolver,
                    CreateUdpResolver) as IRequestResolver;
            for (var x = 0; x < lookupNameParts.Count; x++)
            {
                var currentLookup = string.Join('.', lookupNameParts.Take(x + 1).Reverse());
                if (currentLookup == lookupName)
                {
                    _logger.LogDebug("Reached the final nameserver for {name}", lookupName);
                    var lookupResult = await innerResolver.Resolve(request, cancellationToken).ConfigureAwait(false);
                    pooledAnswers.AddRange(lookupResult.AnswerRecords);
                    pooledAuthorityRecords.AddRange(lookupResult.AuthorityRecords);
                    pooledAdditionalAnswerRecords.AddRange(lookupResult.AdditionalRecords);
                    break;
                }

                var clientRequest = new Request();
                clientRequest.Questions.Add(new Question(new Domain(lookupName), RecordType.SRV));
                clientRequest.RecursionDesired = true;
                clientRequest.OperationCode = OperationCode.Query;
                _logger.LogDebug("Looking up next nameservers via recursive query {currentName}", currentLookup);
                var results = await innerResolver.Resolve(clientRequest, cancellationToken).ConfigureAwait(false);
                if (results is null or not { ResponseCode: ResponseCode.NoError or ResponseCode.NameError })
                {
                    _logger.LogDebug(
                        "Recursive lookup for part {currentName} got a response with an error: {responseCode}: {results}",
                        currentLookup, results.ResponseCode, results);
                    break;
                }

                using var nameServerRecords =
                    results.AdditionalRecords.OfType<IPAddressResourceRecord>().ToPooledList();
                if (nameServerRecords.Count == 0)
                {
                    _logger.LogDebug(
                        "Recursive lookup for part {currentName} got a response without error, but gave no answers: {results}",
                        currentLookup, results);
                    break;
                }

                using var endpoints = nameServerRecords
                    .Where(i => i.Type is RecordType.A or RecordType.AAAA)
                    .Select(answer => new IPEndPoint(GetAddress(answer.Data), 53))
                    .ToPooledList();
                _logger.LogDebug("Got nameservers {nameservers} for recursive part {currentName}",
                    string.Join(", ", endpoints), lookupName);

                innerResolver = _resolverCache.GetMultiResolver(endpoints, CreateParallelResolver, CreateUdpResolver);
            }
        }

        var response = Response.FromRequest(request);
        foreach (var answer in pooledAnswers)
            response.AnswerRecords.Add(answer);
        foreach (var answer in pooledAuthorityRecords)
            response.AuthorityRecords.Add(answer);
        foreach (var answer in pooledAdditionalAnswerRecords)
            response.AdditionalRecords.Add(answer);
        response.ResponseCode =
            pooledAnswers.Count + pooledAuthorityRecords.Count + pooledAdditionalAnswerRecords.Count == 0
                ? ResponseCode.NameError
                : ResponseCode.NoError;
        return response;
    }

    private ParallelResolver CreateParallelResolver(IEnumerable<IRequestResolver> resolvers)
    {
        return new ParallelResolver(resolvers);
    }

    private static UdpRequestResolver CreateUdpResolver(IPEndPoint endPoint)
    {
        return new UdpRequestResolver(endPoint);
    }

    private IPAddress GetAddress(byte[] answerData)
    {
        return new IPAddress(answerData);
    }
}