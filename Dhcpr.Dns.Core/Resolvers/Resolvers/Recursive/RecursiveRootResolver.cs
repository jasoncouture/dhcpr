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

using Microsoft.Extensions.ObjectPool;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

public sealed class RecursiveRootResolver : MultiResolver, IRecursiveResolver
{
    private readonly IResolverCache _resolverCache;
    private readonly ObjectPool<StringBuilder> _stringBuilderPool;
    private readonly ImmutableArray<IPEndPoint> _servers;

    public RecursiveRootResolver(
        IEnumerable<IPEndPoint> servers,
        IResolverCache resolverCache,
        ObjectPool<StringBuilder> stringBuilderPool
    )
    {
        _servers = servers.ToImmutableArray();
        _resolverCache = resolverCache;
        _stringBuilderPool = stringBuilderPool;
        AddResolvers(_servers.Select(i => _resolverCache.GetResolver(i, CreateUdpResolver)).Cast<IRequestResolver>()
            .ToArray());
    }

    private IRequestResolver GetResolver(IEnumerable<IPEndPoint> endPoints, bool withCache = true)
    {
        var resolver = _resolverCache.GetResolver(endPoints, CreateParallelResolver,
            CreateUdpResolver);
        if (withCache)
            return _resolverCache.WrapWithCache(resolver);
        return resolver;
    }

    private static readonly RecordType[] NameServerRecordTypes = { RecordType.A, RecordType.AAAA };

    private bool Recurse
    {
        get => _recurseState.Value;
        set => _recurseState.Value = value;
    }

    private static readonly AsyncLocal<bool> _recurseState = new();

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
        using var labels = request.Questions[0].Name.ToString(Encoding.ASCII).Split('.').ToPooledList();
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

                var resolver = GetResolver(endPoints);
                var lastLabelCount = labels.Count;
                if (labels.Count > 0)
                {
                    if (queryNameBuilder.Length != 0)
                        queryNameBuilder.Insert(0, '.');
                    queryNameBuilder.Insert(0, labels[^1]);
                    // This prevents the list from copying the array.
                    // If we removed at 0, it will copy count-1 to index 0
                    // But it does have a check for when the index is the last element
                    // and skips the array copy.
                    labels.RemoveAt(labels.Count - 1);
                }

                if (lastLabelCount == 0)
                {
                    var question = request.Questions[0];
                    // No cache here, we may get nameservers with the A/AAAA request.
                    // So if we do, we won't want that cached.
                    resolver = GetResolver(endPoints, withCache: false);
                    response = await resolver.Resolve(request, cancellationToken);
                    using var allResponseRecords = response.ToResourceRecordPooledList();
                    if (
                        question.Type is RecordType.A or
                            RecordType.AAAA &&
                        response.AnswerRecords.Any(i => i.Type == question.Type)
                    )
                        return response;
                    if (
                        question.Type is not RecordType.A
                            and not RecordType.AAAA &&
                        allResponseRecords.Any(i => i.Type == question.Type)
                    )
                        return response;
                    resolver = GetResolver(endPoints);
                    if (response.AuthorityRecords.Count > 0 || response.AdditionalRecords.Count > 0)
                    {
                        using var nameserverAddresses =
                            await GetNameServerAddresses(resolver, response, cancellationToken);
                        if (nameserverAddresses.Count > 0)
                        {
                            endPoints.Clear();
                            endPoints.AddRange(AddressRecordsToEndPoints(nameserverAddresses));
                        }

                        continue;
                    }

                    resolver = GetResolver(endPoints, withCache: false);
                    request = new Request(request)
                    {
                        RecursionDesired = true, Id = Random.Shared.Next(0, int.MaxValue)
                    };
                    question = request.Questions[0];
                    question = new Question(question.Name, RecordType.CNAME, RecordClass.ANY);
                    request.Questions.Clear();
                    request.Questions.Add(question);
                    response = await resolver.Resolve(request, cancellationToken);
                    response = response.Clone();
                    response.Questions.Clear();
                    response.Questions.Add(question);
                    return response;
                }

                var currentRequest =
                    new Request(request) { Id = Random.Shared.Next(1, int.MaxValue), RecursionDesired = true };
                currentRequest.Questions.Clear();
                currentRequest.Questions.Add(new Question(new Domain(queryNameBuilder.ToString()), RecordType.NS));

                var currentResponse = await resolver.Resolve(currentRequest, cancellationToken);


                using var additionalRecords =
                    await GetNameServerAddresses(resolver, currentResponse, cancellationToken);
                if (additionalRecords.Count == 0)
                {
                    continue;
                }

                endPoints.Clear();
                endPoints.AddRange(AddressRecordsToEndPoints(additionalRecords));
            }
        }
        finally
        {
            _stringBuilderPool.Return(queryNameBuilder);
        }
    }

    private async ValueTask<PooledList<IPAddressResourceRecord>> GetNameServerAddresses(IRequestResolver resolver,
        IResponse response,
        CancellationToken cancellationToken)
    {
        using var allResponseRecords = response.ToResourceRecordPooledList();
        if (allResponseRecords.Count == 0)
            return ListPool<IPAddressResourceRecord>.Default.Get();

        var additionalRecords = allResponseRecords.OfType<IPAddressResourceRecord>().ToPooledList();
        if (additionalRecords.Count > 0)
        {
            return additionalRecords;
        }

        additionalRecords.AddRange(await ResolveNameServers(resolver, response, cancellationToken));
        if (additionalRecords.Count != 0 || !Recurse)
            return additionalRecords;

        Recurse = true;

        additionalRecords.AddRange(await ResolveNameServers(this, response, cancellationToken));

        Recurse = false;

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
        var additionalRecords = currentResponse.AuthorityRecords
            .Concat(currentResponse.AdditionalRecords)
            .Concat(currentResponse.AnswerRecords)
            .OfType<IPAddressResourceRecord>()
            .ToPooledList();

        if (additionalRecords.Count > 0)
            return additionalRecords;

        foreach (var record in
                 currentResponse.AuthorityRecords.OfType<NameServerResourceRecord>())
        {
            foreach (var recordType in NameServerRecordTypes)
            {
                var newRequest = new Request() { RecursionDesired = true };
                newRequest.Questions.Add(new Question(record.NSDomainName, recordType));
                var nameServerResponse = await dnsResolver.Resolve(newRequest, cancellationToken);

                additionalRecords.AddRange(nameServerResponse.AnswerRecords
                    .OfType<IPAddressResourceRecord>());
                if (additionalRecords.Count > 0)
                    return additionalRecords;
            }
        }

        foreach (var authority in
                 currentResponse.AuthorityRecords.OfType<StartOfAuthorityResourceRecord>())
        {
            foreach (var recordType in NameServerRecordTypes)
            {
                var newRequest = new Request() { RecursionDesired = true };
                newRequest.Questions.Add(new Question(authority.MasterDomainName, recordType));
                var nameServerResponse = await dnsResolver.Resolve(newRequest, cancellationToken)
                    ;
                additionalRecords.AddRange(nameServerResponse.AnswerRecords
                    .OfType<IPAddressResourceRecord>());
                if (additionalRecords.Count > 0)
                    return additionalRecords;
            }
        }

        return additionalRecords;
    }

    private ParallelResolver CreateParallelResolver(IEnumerable<IRequestResolver> resolvers)
    {
        return new ParallelResolver(resolvers);
    }

    private static UdpRequestResolver CreateUdpResolver(IPEndPoint endPoint)
    {
        return new UdpRequestResolver(endPoint, new TcpRequestResolver(endPoint), timeout: 500);
    }
}