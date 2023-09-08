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
using Microsoft.Extensions.ObjectPool;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

public sealed class RecursiveResolver : MultiResolver, IRecursiveResolver
{
    private readonly IResolverCache _resolverCache;
    private readonly IServiceProvider _serviceProvider;
    private readonly ObjectPool<StringBuilder> _stringBuilderPool;
    private readonly ImmutableArray<IPEndPoint> _servers;

    public RecursiveResolver(
        IEnumerable<IPEndPoint> servers,
        IResolverCache resolverCache,
        IServiceProvider serviceProvider,
        ObjectPool<StringBuilder> stringBuilderPool
    )
    {
        _servers = servers.ToImmutableArray();
        _resolverCache = resolverCache;
        _serviceProvider = serviceProvider;
        _stringBuilderPool = stringBuilderPool;
        AddResolvers(_servers.Select(i => _resolverCache.GetResolver(i, CreateUdpResolver)).Cast<IRequestResolver>()
            .ToArray());
    }

    private IRequestResolver GetResolver(IEnumerable<IPEndPoint> endPoints)
    {
        var resolver = _resolverCache.GetResolver(endPoints, CreateParallelResolver,
            CreateUdpResolver);
        return resolver;
    }

    private static readonly RecordType[] NameServerRecordTypes = new[] { RecordType.A, RecordType.AAAA };

    [SuppressMessage("ReSharper", "AccessToDisposedClosure")]
    public override async Task<IResponse?> Resolve(
        IRequest request,
        CancellationToken cancellationToken = default
    )
    {
        if (_servers.Length == 0) return null;
        using var pooledAnswers = ListPool<IResourceRecord>.Default.Get();
        using var pooledAuthorityRecords = ListPool<IResourceRecord>.Default.Get();
        using var pooledAdditionalAnswerRecords = ListPool<IResourceRecord>.Default.Get();
        using var endPoints = _servers.ToPooledList();
        using var labels = request.Questions[0].Name.ToString(Encoding.ASCII).Split('.').Reverse().ToPooledList();
        var question = request.Questions[0];
        var queryNameBuilder = _stringBuilderPool.Get();
        int maxIteration = labels.Count + 10;
        IResponse? response = null;
        try
        {
            while (true)
            {
                maxIteration -= 1;
                if (maxIteration <= 0)
                {
                    return null;
                }

                var lastCount = labels.Count;
                var resolver = GetResolver(endPoints);
                if (labels.Count > 0)
                {
                    if (queryNameBuilder.Length != 0)
                        queryNameBuilder.Insert(0, '.');
                    queryNameBuilder.Insert(0, labels[0]);
                    labels.RemoveAt(0);
                }

                response = await resolver.Resolve(request, cancellationToken).ConfigureAwait(false);

                if (response.AnswerRecords.Any(i =>
                        i.Type == RecordType.CNAME ||
                        i.Type == question.Type ||
                        (question.Type == RecordType.A && i.Type is RecordType.AAAA or RecordType.CNAME) ||
                        (question.Type == RecordType.AAAA && i.Type == RecordType.CNAME)))
                {
                    return new Response(response) { Id = request.Id };
                }

                if (lastCount == 0)
                    return null;

                var currentRequest =
                    new Request(request) { Id = Random.Shared.Next(1, int.MaxValue), RecursionDesired = true };
                currentRequest.Questions.Clear();
                currentRequest.Questions.Add(new Question(new Domain(queryNameBuilder.ToString()), RecordType.NS,
                    RecordClass.IN));

                var currentResponse = await resolver.Resolve(currentRequest, cancellationToken).ConfigureAwait(false);
                if (currentResponse.ResponseCode != ResponseCode.NoError)
                {
                    continue;
                }


                using var additionalRecords =
                    await GetNameServerAddresses(currentResponse, cancellationToken).ConfigureAwait(false);

                endPoints.Clear();
                endPoints.AddRange(AddressRecordsToEndPoints(additionalRecords));
            }
        }
        finally
        {
            _stringBuilderPool.Return(queryNameBuilder);
        }
    }

    private async ValueTask<PooledList<IPAddressResourceRecord>> GetNameServerAddresses(IResponse response,
        CancellationToken cancellationToken)
    {
        using var allResponseRecords = response.AnswerRecords
            .Union(response.AuthorityRecords)
            .Union(response.AdditionalRecords)
            .ToPooledList();
        var additionalRecords = allResponseRecords.OfType<IPAddressResourceRecord>().ToPooledList();
        if (additionalRecords.Count > 0)
        {
            return additionalRecords;
        }

        await using var scope = _serviceProvider.CreateAsyncScope();
        var dnsResolver = scope.ServiceProvider.GetRequiredService<IDnsResolver>();
        using var result = await ResolveNameServers(dnsResolver, response, cancellationToken)
            .ConfigureAwait(false);

        additionalRecords.AddRange(result);

        return additionalRecords;
    }

    private IEnumerable<IPEndPoint> AddressRecordsToEndPoints(IEnumerable<IPAddressResourceRecord> records)
    {
        return records.Select(i => new IPEndPoint(i.IPAddress, 53));
    }

    private static async Task<PooledList<IPAddressResourceRecord>> ResolveNameServers(IRequestResolver dnsResolver,
        IResponse currentResponse,
        CancellationToken cancellationToken)
    {
        var additionalRecords = ListPool<IPAddressResourceRecord>.Default.Get();
        await Parallel.ForEachAsync(
            currentResponse.AuthorityRecords.OfType<NameServerResourceRecord>(),
            cancellationToken,
            async (authority, ctx) =>
            {
                var newRequest = new Request();
                foreach (var recordType in NameServerRecordTypes)
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
                foreach (var recordType in NameServerRecordTypes)
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

        return additionalRecords;
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