using System.Collections.Immutable;
using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Resolvers.Caching;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.UnitTests;

public class RecursiveRootResolverTests
{
    private static readonly IPEndPoint RootServer = new(IPAddress.Parse("198.41.0.4"), 53);
    private static readonly IPEndPoint ComServer = new(IPAddress.Parse("192.5.6.30"), 53);
    private static readonly IPEndPoint GoogleNs = new(IPAddress.Parse("216.239.32.10"), 53);
    private static readonly IPAddress GoogleWwwAddress = IPAddress.Parse("142.250.80.36");
    private static readonly IPAddress UnrelatedAddress = IPAddress.Parse("1.2.3.4");
    private static readonly IPAddress NsResolvedAddress = IPAddress.Parse("9.9.9.9");

    [Fact]
    public async Task GoogleLikeNodataKeepsParentNameservers()
    {
        var factory = new ScriptedDomainClientFactory(request =>
        {
            var name = request.Questions[0].Name.ToString();
            var type = request.Questions[0].Type;

            if (type == DomainRecordType.NS && name.Equals("com", StringComparison.OrdinalIgnoreCase))
            {
                return Referral("com", "a.gtld-servers.net", ComServer.Address);
            }

            if (type == DomainRecordType.NS && name.Equals("google.com", StringComparison.OrdinalIgnoreCase))
            {
                return Referral("google.com", "ns1.google.com", GoogleNs.Address);
            }

            // Leaf NS probe: authoritative NODATA with SOA only (no NS, no glue).
            if (type == DomainRecordType.NS && name.Equals("www.google.com", StringComparison.OrdinalIgnoreCase))
            {
                return NodataWithSoa("www.google.com");
            }

            if (type == DomainRecordType.A && name.Equals("www.google.com", StringComparison.OrdinalIgnoreCase))
            {
                return Answer(request, ARecord("www.google.com", GoogleWwwAddress));
            }

            return EmptyNoError(request);
        });

        var resolver = CreateResolver(factory);
        var request = DomainMessage.CreateRequest("www.google.com");
        var context = new DomainMessageContext(null, null, request);

        var result = await resolver.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NoError, result!.Flags.ResponseCode);
        Assert.Contains(result.Records.Answers, r =>
            r.Type == DomainRecordType.A &&
            ((IPAddressData)r.Data).Address.Equals(GoogleWwwAddress));
        Assert.DoesNotContain(factory.QueriedEndPoints, ep => ep.Address.Equals(GoogleWwwAddress));
        Assert.Contains(factory.QueriedEndPoints, ep => ep.Address.Equals(GoogleNs.Address));
    }

    [Fact]
    public async Task ReferralUsesMatchingGlueOnly()
    {
        IPEndPoint? nextHopAfterCom = null;
        var factory = new ScriptedDomainClientFactory(request =>
        {
            var name = request.Questions[0].Name.ToString();
            var type = request.Questions[0].Type;

            if (type == DomainRecordType.NS && name.Equals("com", StringComparison.OrdinalIgnoreCase))
            {
                return new DomainMessage(
                    request.Id,
                    ResponseFlags(),
                    request.Questions,
                    new DomainResourceRecords(
                        ImmutableArray<DomainResourceRecord>.Empty,
                        ImmutableArray.Create(
                            NsRecord("com", "a.gtld-servers.net")),
                        ImmutableArray.Create(
                            ARecord("a.gtld-servers.net", ComServer.Address),
                            ARecord("unrelated.example", UnrelatedAddress))));
            }

            if (type == DomainRecordType.NS && name.Equals("example.com", StringComparison.OrdinalIgnoreCase))
            {
                return NodataWithSoa("example.com");
            }

            if (type == DomainRecordType.A && name.Equals("example.com", StringComparison.OrdinalIgnoreCase))
            {
                return Answer(request, ARecord("example.com", IPAddress.Parse("93.184.216.34")));
            }

            return EmptyNoError(request);
        }, onUdpQuery: (_, endPoint) =>
        {
            if (endPoint.Address.Equals(ComServer.Address))
                nextHopAfterCom = endPoint;
        });

        var resolver = CreateResolver(factory);
        var request = DomainMessage.CreateRequest("example.com");
        var result = await resolver.ProcessAsync(new DomainMessageContext(null, null, request), CancellationToken.None);

        Assert.NotNull(result);
        Assert.Contains(factory.QueriedEndPoints, ep => ep.Address.Equals(ComServer.Address));
        Assert.DoesNotContain(factory.QueriedEndPoints, ep => ep.Address.Equals(UnrelatedAddress));
        Assert.NotNull(nextHopAfterCom);
    }

    [Fact]
    public async Task ReferralWithoutGlueResolvesNsNamesInternally()
    {
        var factory = new ScriptedDomainClientFactory(request =>
        {
            var name = request.Questions[0].Name.ToString();
            var type = request.Questions[0].Type;

            if (type == DomainRecordType.NS && name.Equals("com", StringComparison.OrdinalIgnoreCase))
            {
                return new DomainMessage(
                    request.Id,
                    ResponseFlags(),
                    request.Questions,
                    new DomainResourceRecords(
                        ImmutableArray<DomainResourceRecord>.Empty,
                        ImmutableArray.Create(NsRecord("com", "a.gtld-servers.net")),
                        ImmutableArray<DomainResourceRecord>.Empty));
            }

            if (type == DomainRecordType.A && name.Equals("a.gtld-servers.net", StringComparison.OrdinalIgnoreCase))
            {
                return Answer(request, ARecord("a.gtld-servers.net", NsResolvedAddress));
            }

            if (type == DomainRecordType.AAAA && name.Equals("a.gtld-servers.net", StringComparison.OrdinalIgnoreCase))
            {
                return EmptyNoError(request);
            }

            if (type == DomainRecordType.NS && name.Equals("example.com", StringComparison.OrdinalIgnoreCase))
            {
                return NodataWithSoa("example.com");
            }

            if (type == DomainRecordType.A && name.Equals("example.com", StringComparison.OrdinalIgnoreCase))
            {
                return Answer(request, ARecord("example.com", IPAddress.Parse("93.184.216.34")));
            }

            return EmptyNoError(request);
        });

        var resolver = CreateResolver(factory);
        var request = DomainMessage.CreateRequest("example.com");
        var result = await resolver.ProcessAsync(new DomainMessageContext(null, null, request), CancellationToken.None);

        Assert.NotNull(result);
        Assert.Contains(factory.QueriedEndPoints, ep => ep.Address.Equals(NsResolvedAddress));
        Assert.Contains(factory.InternalQueries,
            q => q.Equals("a.gtld-servers.net/A", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task UnrelatedAddressInAdditionalIsNotUsedAsNameserver()
    {
        var factory = new ScriptedDomainClientFactory(request =>
        {
            var name = request.Questions[0].Name.ToString();
            var type = request.Questions[0].Type;

            if (type == DomainRecordType.NS && name.Equals("com", StringComparison.OrdinalIgnoreCase))
            {
                return new DomainMessage(
                    request.Id,
                    ResponseFlags(),
                    request.Questions,
                    new DomainResourceRecords(
                        ImmutableArray<DomainResourceRecord>.Empty,
                        ImmutableArray.Create(NsRecord("com", "a.gtld-servers.net")),
                        ImmutableArray.Create(
                            ARecord("cdn.example.net", UnrelatedAddress),
                            ARecord("a.gtld-servers.net", ComServer.Address))));
            }

            if (type == DomainRecordType.NS &&
                (name.Equals("facebook.com", StringComparison.OrdinalIgnoreCase) ||
                 name.Equals("www.facebook.com", StringComparison.OrdinalIgnoreCase)))
            {
                return NodataWithSoa(name);
            }

            if (type == DomainRecordType.A && name.Equals("www.facebook.com", StringComparison.OrdinalIgnoreCase))
            {
                return Answer(request, ARecord("www.facebook.com", IPAddress.Parse("157.240.3.35")));
            }

            return EmptyNoError(request);
        });

        var resolver = CreateResolver(factory);
        var request = DomainMessage.CreateRequest("www.facebook.com");
        await resolver.ProcessAsync(new DomainMessageContext(null, null, request), CancellationToken.None);

        Assert.DoesNotContain(factory.QueriedEndPoints, ep => ep.Address.Equals(UnrelatedAddress));
        Assert.Contains(factory.QueriedEndPoints, ep => ep.Address.Equals(ComServer.Address));
    }

    [Fact]
    public async Task TwoLabelNameQueriesZoneNsThenAnswers()
    {
        var queried = new List<IPEndPoint>();
        var factory = new ScriptedDomainClientFactory(request =>
        {
            var name = request.Questions[0].Name.ToString();
            var type = request.Questions[0].Type;

            if (type == DomainRecordType.NS && name.Equals("com", StringComparison.OrdinalIgnoreCase))
                return Referral("com", "a.gtld-servers.net", ComServer.Address);

            if (type == DomainRecordType.NS && name.Equals("google.com", StringComparison.OrdinalIgnoreCase))
                return Referral("google.com", "ns1.google.com", GoogleNs.Address);

            if (type == DomainRecordType.A && name.Equals("google.com", StringComparison.OrdinalIgnoreCase))
            {
                // TLD would only refer; authoritative NS answers.
                if (queried.Any(ep => ep.Address.Equals(GoogleNs.Address)))
                    return Answer(request, ARecord("google.com", GoogleWwwAddress));
                return Referral("google.com", "ns1.google.com", GoogleNs.Address);
            }

            return EmptyNoError(request);
        }, onUdpQuery: (_, endPoint) => queried.Add(endPoint));

        var resolver = CreateResolver(factory);
        var request = DomainMessage.CreateRequest("google.com");
        var result = await resolver.ProcessAsync(new DomainMessageContext(null, null, request), CancellationToken.None);

        Assert.NotNull(result);
        Assert.Contains(result!.Records.Answers, r =>
            r.Type == DomainRecordType.A &&
            ((IPAddressData)r.Data).Address.Equals(GoogleWwwAddress));
        Assert.Contains(factory.QueriedEndPoints, ep => ep.Address.Equals(GoogleNs.Address));
    }

    [Fact]
    public async Task SecondLookupReusesCachedComNs()
    {
        var cache = CreateCache();
        var comNsQueries = 0;
        var factory = new ScriptedDomainClientFactory(request =>
        {
            var name = request.Questions[0].Name.ToString();
            var type = request.Questions[0].Type;

            if (type == DomainRecordType.NS && name.Equals("com", StringComparison.OrdinalIgnoreCase))
            {
                comNsQueries++;
                return Referral("com", "a.gtld-servers.net", ComServer.Address);
            }

            if (type == DomainRecordType.NS && name.Equals("google.com", StringComparison.OrdinalIgnoreCase))
                return Referral("google.com", "ns1.google.com", GoogleNs.Address);

            if (type == DomainRecordType.NS && name.Equals("example.com", StringComparison.OrdinalIgnoreCase))
                return NodataWithSoa("example.com");

            if (type == DomainRecordType.A && name.Equals("www.google.com", StringComparison.OrdinalIgnoreCase))
                return Answer(request, ARecord("www.google.com", GoogleWwwAddress));

            if (type == DomainRecordType.A && name.Equals("example.com", StringComparison.OrdinalIgnoreCase))
                return Answer(request, ARecord("example.com", IPAddress.Parse("93.184.216.34")));

            if (type == DomainRecordType.NS &&
                (name.Equals("www.google.com", StringComparison.OrdinalIgnoreCase)))
                return NodataWithSoa(name);

            return EmptyNoError(request);
        });

        var resolver = CreateResolver(factory, cache);
        await resolver.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("www.google.com")),
            CancellationToken.None);
        Assert.Equal(1, comNsQueries);

        await resolver.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("example.com")),
            CancellationToken.None);
        Assert.Equal(1, comNsQueries);
    }

    private static RecursiveRootResolver CreateResolver(
        ScriptedDomainClientFactory factory,
        IDnsResponseCache? cache = null)
    {
        var options = new TestOptionsMonitor(new RootServerConfiguration
        {
            Addresses = new[] { RootServer.ToString() }
        });
        return new RecursiveRootResolver(
            options,
            factory,
            cache ?? CreateCache(),
            NullLogger<RecursiveRootResolver>.Instance);
    }

    private static DnsResponseCache CreateCache()
        => new(new MemoryCache(new MemoryCacheOptions { SizeLimit = 10_000 }));

    private static DomainMessage Referral(string zone, string nsName, IPAddress glue)
        => new(
            1,
            ResponseFlags(),
            ImmutableArray.Create(new DomainQuestion(new DomainLabels(zone), DomainRecordType.NS, DomainRecordClass.IN)),
            new DomainResourceRecords(
                ImmutableArray<DomainResourceRecord>.Empty,
                ImmutableArray.Create(NsRecord(zone, nsName)),
                ImmutableArray.Create(ARecord(nsName, glue))));

    private static DomainMessage NodataWithSoa(string name)
        => new(
            1,
            ResponseFlags(authoritative: true),
            ImmutableArray.Create(new DomainQuestion(new DomainLabels(name), DomainRecordType.NS, DomainRecordClass.IN)),
            new DomainResourceRecords(
                ImmutableArray<DomainResourceRecord>.Empty,
                ImmutableArray.Create(new DomainResourceRecord(
                    new DomainLabels(name),
                    DomainRecordType.SOA,
                    DomainRecordClass.IN,
                    TimeSpan.FromSeconds(60),
                    new StartOfAuthorityData(1, TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(60),
                        TimeSpan.FromSeconds(60), TimeSpan.FromSeconds(60)))),
                ImmutableArray<DomainResourceRecord>.Empty));

    private static DomainMessage Answer(DomainMessage request, params DomainResourceRecord[] answers)
        => DomainMessage.CreateResponse(request, answers, responseCode: DomainResponseCode.NoError);

    private static DomainMessage EmptyNoError(DomainMessage request)
        => DomainMessage.CreateResponse(request, DomainResourceRecords.Empty, DomainResponseCode.NoError);

    private static DomainMessageFlags ResponseFlags(bool authoritative = false)
        => new(true, DomainOperationCode.Query, authoritative, false, false, false, false, false,
            DomainResponseCode.NoError);

    private static DomainResourceRecord NsRecord(string owner, string target)
        => new(new DomainLabels(owner), DomainRecordType.NS, DomainRecordClass.IN, TimeSpan.FromSeconds(60),
            new NameData(new DomainLabels(target)));

    private static DomainResourceRecord ARecord(string owner, IPAddress address)
        => new(new DomainLabels(owner), DomainRecordType.A, DomainRecordClass.IN, TimeSpan.FromSeconds(60),
            new IPAddressData(address));

    private sealed class TestOptionsMonitor : IOptionsMonitor<RootServerConfiguration>
    {
        public TestOptionsMonitor(RootServerConfiguration current) => CurrentValue = current;
        public RootServerConfiguration CurrentValue { get; }
        public RootServerConfiguration Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<RootServerConfiguration, string?> listener) => null;
    }

    private sealed class ScriptedDomainClientFactory : IDomainClientFactory
    {
        private readonly Func<DomainMessage, DomainMessage> _script;
        private readonly Action<DomainMessage, IPEndPoint>? _onUdpQuery;

        public ScriptedDomainClientFactory(
            Func<DomainMessage, DomainMessage> script,
            Action<DomainMessage, IPEndPoint>? onUdpQuery = null)
        {
            _script = script;
            _onUdpQuery = onUdpQuery;
        }

        public List<IPEndPoint> QueriedEndPoints { get; } = new();
        public List<string> InternalQueries { get; } = new();

        public ValueTask<IDomainClient> GetParallelDomainClient(IEnumerable<DomainClientOptions> options,
            CancellationToken cancellationToken = default)
        {
            var endPoints = options.Select(o => o.EndPoint).ToArray();
            return ValueTask.FromResult<IDomainClient>(new ScriptedClient(this, endPoints, internalClient: false));
        }

        public ValueTask<IDomainClient> GetDomainClient(DomainClientOptions options,
            CancellationToken cancellationToken = default)
        {
            if (options.Type == DomainClientType.Internal)
                return ValueTask.FromResult<IDomainClient>(new ScriptedClient(this, Array.Empty<IPEndPoint>(), true));

            return ValueTask.FromResult<IDomainClient>(
                new ScriptedClient(this, new[] { options.EndPoint }, false));
        }

        private DomainMessage Handle(DomainMessage request, IPEndPoint[] endPoints, bool internalClient)
        {
            if (internalClient)
            {
                InternalQueries.Add($"{request.Questions[0].Name}/{request.Questions[0].Type}");
            }
            else
            {
                foreach (var endPoint in endPoints)
                {
                    QueriedEndPoints.Add(endPoint);
                    _onUdpQuery?.Invoke(request, endPoint);
                }
            }

            var response = _script(request);
            return response with { Id = request.Id };
        }

        private sealed class ScriptedClient : IDomainClient
        {
            private readonly ScriptedDomainClientFactory _factory;
            private readonly IPEndPoint[] _endPoints;
            private readonly bool _internalClient;

            public ScriptedClient(ScriptedDomainClientFactory factory, IPEndPoint[] endPoints, bool internalClient)
            {
                _factory = factory;
                _endPoints = endPoints;
                _internalClient = internalClient;
            }

            public ValueTask<DomainMessage> SendAsync(DomainMessage message, CancellationToken cancellationToken)
                => ValueTask.FromResult(_factory.Handle(message, _endPoints, _internalClient));
        }
    }
}
