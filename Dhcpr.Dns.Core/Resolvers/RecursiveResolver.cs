using System.Diagnostics.CodeAnalysis;
using System.Net;

using Dhcpr.Core.Linq;

using DNS.Client.RequestResolver;
using DNS.Protocol;
using DNS.Protocol.ResourceRecords;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core.Resolvers;

public sealed class RecursiveResolver : MultiResolver, IRecursiveResolver
{
    private readonly IResolverCache _resolverCache;
    private readonly ILogger<RecursiveResolver> _logger;
    private readonly IServiceProvider _serviceProvider;
    private readonly IEnumerable<IPEndPoint> _servers;

    public RecursiveResolver(IEnumerable<IPEndPoint> servers, IResolverCache resolverCache,
        ILogger<RecursiveResolver> logger, IServiceProvider serviceProvider)
    {
        _servers = servers;
        _resolverCache = resolverCache;
        _logger = logger;
        _serviceProvider = serviceProvider;
        AddResolvers(servers.Select(i => _resolverCache.GetResolver(i, CreateUdpResolver)).Cast<IRequestResolver>()
            .ToArray());
        _logger.LogDebug("Recursive resolver created for {server}", servers);
    }

    private IRequestResolver GetResolver(IEnumerable<IPEndPoint> endPoints)
    {
        return _resolverCache.GetMultiResolver<ParallelResolver, UdpRequestResolver>(endPoints, CreateParallelResolver,
            CreateUdpResolver);
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
        while (true)
        {
            var currentResolver = GetResolver(endPoints);
            var currentResponse = await currentResolver.Resolve(request, cancellationToken).ConfigureAwait(false);
            if (currentResponse.ResponseCode == ResponseCode.NoError && (currentResponse.AuthorityRecords.Any() || currentResponse.AdditionalRecords.Any()) && currentResponse.AnswerRecords.Count == 0)
            {
                using var additionalRecords = currentResponse.AdditionalRecords.OfType<IPAddressResourceRecord>().ToPooledList();
                if (additionalRecords.Count == 0)
                {
                    var dnsResolver = _serviceProvider.GetRequiredService<IDnsResolver>();
                    additionalRecords.Clear();
                    await Parallel.ForEachAsync(
                        currentResponse.AuthorityRecords.OfType<NameServerResourceRecord>(),
                        cancellationToken,
                        async (authority, ctx) =>
                        {
                            var newRequest = new Request(request);
                            foreach(var recordType in _nameServerRecordTypes) {
                                newRequest.Id = Random.Shared.Next();
                                newRequest.Questions.Clear();
                                newRequest.Questions.Add(new Question(authority.NSDomainName, recordType));
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
            }
            else
            {
                return currentResponse;
            }
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

    private IPAddress GetAddress(byte[] answerData)
    {
        return new IPAddress(answerData);
    }
}