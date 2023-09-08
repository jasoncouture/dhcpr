using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text;

using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Resolvers.Caching;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Abstractions;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Wrappers;

using DNS.Client.RequestResolver;
using DNS.Protocol;
using DNS.Protocol.ResourceRecords;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.ObjectPool;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

public sealed class RecursiveResolver : MultiResolver, IRecursiveResolver
{
    private readonly IResolverCache _resolverCache;
    private readonly ILogger<RecursiveResolver> _logger;
    private readonly IServiceProvider _serviceProvider;
    private readonly ObjectPool<StringBuilder> _stringBuilderPool;
    private readonly ImmutableArray<IPEndPoint> _servers;

    public RecursiveResolver(IEnumerable<IPEndPoint> servers, IResolverCache resolverCache,
        ILogger<RecursiveResolver> logger, IServiceProvider serviceProvider,
        ObjectPool<StringBuilder> stringBuilderPool)
    {
        _servers = servers.ToImmutableArray();
        _resolverCache = resolverCache;
        _logger = logger;
        _serviceProvider = serviceProvider;
        _stringBuilderPool = stringBuilderPool;
        AddResolvers(_servers.Select(i => _resolverCache.GetResolver(i, CreateUdpResolver)).Cast<IRequestResolver>()
            .ToArray());
    }

    private IRequestResolver GetResolver(IEnumerable<IPEndPoint> endPoints)
    {
        var resolver = _resolverCache.GetResolver(endPoints, CreateParallelResolver,
            CreateUdpResolver);
        return _resolverCache.GetCacheForResolver(resolver);
    }

    private static readonly RecordType[] _nameServerRecordTypes = new[] { RecordType.A, RecordType.AAAA };

    [SuppressMessage("ReSharper", "AccessToDisposedClosure")]
    public override async Task<IResponse?> Resolve(IRequest request,
        CancellationToken cancellationToken = new CancellationToken())
    {
        using var pooledAnswers = ListPool<IResourceRecord>.Default.Get();
        using var pooledAuthorityRecords = ListPool<IResourceRecord>.Default.Get();
        using var pooledAdditionalAnswerRecords = ListPool<IResourceRecord>.Default.Get();
        using var endPoints = _servers.ToPooledList();
        using var domainParts = request.Questions[0].Name.ToString(Encoding.ASCII).Split('.').Reverse().ToPooledList();
        var queryNameBuilder = _stringBuilderPool.Get();
        var currentRequest = new Request(request);
        IResponse? lastResponse = null;
        int maxIteration = domainParts.Count + 10;
        try
        {
            while (true)
            {
                maxIteration -= 1;
                if (maxIteration <= 0)
                {
                    var response = Response.FromRequest(request);
                    response.ResponseCode = ResponseCode.ServerFailure;
                    return response;
                }
                var resolver = GetResolver(endPoints);
                if (domainParts.Count > 0)
                {
                    if (queryNameBuilder.Length != 0)
                        queryNameBuilder.Insert(0, '.');
                    queryNameBuilder.Insert(0, domainParts[0]);
                    domainParts.RemoveAt(0);
                }

                if (domainParts.Count == 0)
                {
                    _logger.LogDebug("Sending client request to final nameservers: {nameservers} {request}", endPoints, request);
                    var response = await resolver.Resolve(request, cancellationToken).ConfigureAwait(false); ;
                    _logger.LogDebug("Response from {nameservers} is {response}", endPoints, response);
                    if (response.AnswerRecords.Count != 0 || response.ResponseCode == ResponseCode.NameError)
                    {
                        return response;
                    }
                    if (response is { AuthorityRecords.Count: 0, AdditionalRecords.Count: 0 } or not { ResponseCode: ResponseCode.NoError })
                        return response;
                    _logger.LogDebug("Nameservers didn't give an error, and provided authority records. Recursing one more time.");
                    //lastResponse = response;
                }


                currentRequest.Id = Random.Shared.Next(1, int.MaxValue);
                currentRequest.Questions.Clear();
                currentRequest.Questions.Add(new Question(new Domain(queryNameBuilder.ToString()), RecordType.NS,
                    RecordClass.ANY)); ;

                _logger.LogDebug("Looking for nameservers for {fragment}", queryNameBuilder);

                var currentResponse = await resolver.Resolve(currentRequest, cancellationToken).ConfigureAwait(false);
                if (currentResponse.ResponseCode != ResponseCode.NoError)
                {
                    if (domainParts.Count == 1) continue;
                    _logger.LogDebug("DNS Resolution failed during recursion. Current fragment is: {fragment}",
                        queryNameBuilder);
                    var response = Response.FromRequest(request);
                    response.ResponseCode = ResponseCode.NameError;
                    return response;
                }

                using var additionalRecords = currentResponse.AdditionalRecords.OfType<IPAddressResourceRecord>()
                    .ToPooledList();
                if (additionalRecords.Count == 0)
                {
                    var dnsResolver = _serviceProvider.GetRequiredService<IDnsResolver>();
                    additionalRecords.Clear();
                    await Parallel.ForEachAsync(
                        currentResponse.AuthorityRecords.OfType<NameServerResourceRecord>(),
                        cancellationToken,
                        async (authority, ctx) =>
                        {
                            var newRequest = new Request();
                            foreach (var recordType in _nameServerRecordTypes)
                            {
                                newRequest.Questions.Add(new Question(authority.NSDomainName, recordType));
                                var nameServerResponse = await dnsResolver.Resolve(newRequest, cancellationToken)
                                    .ConfigureAwait(false);
                                if (nameServerResponse.ResponseCode != ResponseCode.NoError) continue;
                                lock (additionalRecords)
                                    additionalRecords.AddRange(nameServerResponse.AnswerRecords
                                        .OfType<IPAddressResourceRecord>());
                            }
                        }).ConfigureAwait(false);

                    await Parallel.ForEachAsync(
                        currentResponse.AuthorityRecords.OfType<StartOfAuthorityResourceRecord>(),
                        cancellationToken,
                        async (authority, ctx) =>
                        {
                            var newRequest = new Request();
                            foreach (var recordType in _nameServerRecordTypes)
                            {
                                newRequest.Questions.Add(new Question(authority.MasterDomainName, recordType));
                                var nameServerResponse = await dnsResolver.Resolve(newRequest, cancellationToken)
                                    .ConfigureAwait(false);
                                if (nameServerResponse.ResponseCode != ResponseCode.NoError) continue;
                                lock (additionalRecords)
                                    additionalRecords.AddRange(nameServerResponse.AnswerRecords
                                        .OfType<IPAddressResourceRecord>());
                            }
                        }).ConfigureAwait(false);
                    if (additionalRecords.Count == 0)
                    {
                        var response = Response.FromRequest(request);
                        response.ResponseCode = ResponseCode.NameError;
                        return response;
                    }
                }

                endPoints.Clear();
                endPoints.AddRange(
                    additionalRecords.Select(i => new IPEndPoint(i.IPAddress, 53)));
                _logger.LogDebug("Found nameservers for {fragment}, recursing to: {nameservers}", queryNameBuilder,
                    endPoints);
            }
        }
        finally
        {
            _stringBuilderPool.Return(queryNameBuilder);
        }
    }

    private ParallelResolver CreateParallelResolver(IEnumerable<IRequestResolver> resolvers)
    {
        return new ParallelResolver(resolvers);
    }

    private static UdpRequestResolver CreateUdpResolver(IPEndPoint endPoint)
    {
        return new UdpRequestResolver(endPoint);
    }
}