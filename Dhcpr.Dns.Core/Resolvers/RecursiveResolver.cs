using System.Diagnostics;
using System.Diagnostics.CodeAnalysis;
using System.Net;

using DNS.Client;
using DNS.Client.RequestResolver;
using DNS.Protocol;
using DNS.Protocol.ResourceRecords;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core;

public record struct QueryCacheKey(string Domain, RecordType Type, RecordClass Class, OperationCode OperationCode)
{
    public QueryCacheKey(IRequest request, IMessageEntry question) : this(question.Name.ToString()!, question.Type,
        question.Class, request.OperationCode)
    {
    }
}

public record class QueryCacheData(byte[] Payload, DateTimeOffset Created)
{
    public QueryCacheData(IResponse response) : this(response.ToArray(), DateTimeOffset.Now) { }
}

public interface IDnsCache
{
    bool TryGetCachedResponse(IRequest request, [NotNullWhen(true)] out IResponse? response);
    void TryAddCacheEntry(IRequest request, IResponse response);
}

public class DnsCache : IDnsCache
{
    private readonly IMemoryCache _memoryCache;

    public DnsCache(IMemoryCache memoryCache)
    {
        _memoryCache = memoryCache;
    }

    public bool TryGetCachedResponse(IRequest request, [NotNullWhen(true)] out IResponse? response)
    {
        response = null;
        if (request.Questions.Count != 1) return false;
        var key = new QueryCacheKey(request, request.Questions[0]);
        if (_memoryCache.TryGetValue(key, out QueryCacheData? data) && data is not null)
        {
            response = Response.FromArray(data.Payload);
            response.Id = request.Id;
            response.Questions.Clear();
            response.Questions.Add(request.Questions[0]);
            // TODO: Update answers with adjusted TTL
            return true;
        }

        return false;
    }

    public void TryAddCacheEntry(IRequest request, IResponse response)
    {
        if (request.Questions.Count != 1) return;
        using var timeToLivePooledList =
            response.AnswerRecords.Concat(response.AdditionalRecords).Concat(response.AuthorityRecords)
                .Select(i => i.TimeToLive)
                .OrderBy(i => i)
                .ToPooledList();
        if (timeToLivePooledList.Count == 0) return;
        var cacheTimeToLive = timeToLivePooledList.First();
        if (cacheTimeToLive <= TimeSpan.Zero) return;

        var cacheSlidingExpiration =
            TimeSpan.FromSeconds(Math.Floor(Math.Min((cacheTimeToLive / 4).TotalSeconds, 10.0)));
        

        var key = new QueryCacheKey(request, request.Questions[0]);
        var cacheEntry = _memoryCache.CreateEntry(key);
        cacheEntry.Value = new QueryCacheData(response);
        cacheEntry.AbsoluteExpirationRelativeToNow = cacheTimeToLive;
        if (cacheSlidingExpiration < cacheTimeToLive)
        {
            cacheEntry.SlidingExpiration = cacheSlidingExpiration;
        }

        cacheEntry.Priority = CacheItemPriority.High;
    }
}

public interface IRecursiveResolver : IMultiResolver
{
}

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