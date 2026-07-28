using System.Collections.Immutable;
using System.Net;

using Dhcpr.Dns.Core.Authoritative;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Protocol.Zone;
using Dhcpr.Dns.Core.Resolvers.Caching;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Forwarder;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;
using Dhcpr.Dns.Core.RootZone;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.UnitTests;

public class AuthoritativeZoneTests
{
    private const string FooBarZone = """
        $ORIGIN foo.bar.
        $TTL 3600
        @ IN SOA ns.foo.bar. hostmaster.foo.bar. ( 1 7200 3600 1209600 3600 )
        @ IN NS ns.foo.bar.
        ns IN A 192.0.2.1
        www IN A 192.0.2.10
        * IN A 192.0.2.99
        child IN NS ns.child.foo.bar.
        ns.child IN A 192.0.2.50
        """;

    [Fact]
    public void FindZone_DeepestApex_StopsOnMissingEdge()
    {
        var store = new AuthoritativeZoneStore();
        store.Publish([BuildZone(FooBarZone, "foo.bar.bind")]);

        Assert.Null(store.FindZone("baz.bar"));
        Assert.Equal("foo.bar", store.FindZone("inner.zone.foo.bar")!.Apex);
        Assert.Equal("foo.bar", store.FindZone("www.foo.bar")!.Apex);
    }

    [Fact]
    public void FindZone_SiblingChildDoesNotSteal()
    {
        var parent = BuildZone(FooBarZone, "foo.bar.bind");
        var child = BuildZone("""
            $ORIGIN a.zone.foo.bar.
            $TTL 3600
            @ IN SOA ns.a.zone.foo.bar. host.a.zone.foo.bar. ( 1 7200 3600 1209600 3600 )
            @ IN NS ns.a.zone.foo.bar.
            ns IN A 192.0.2.60
            """, "a.zone.foo.bar.bind");

        var store = new AuthoritativeZoneStore();
        store.Publish([parent, child]);

        Assert.Equal("foo.bar", store.FindZone("inner.zone.foo.bar")!.Apex);
        Assert.Equal("a.zone.foo.bar", store.FindZone("x.a.zone.foo.bar")!.Apex);
    }

    [Fact]
    public void AnswerEngine_AaForExactName()
    {
        var zone = BuildZone(FooBarZone, "foo.bar.bind");
        var request = DomainMessage.CreateRequest("www.foo.bar");
        var result = ZoneAnswerEngine.Answer(zone, request);

        Assert.Equal(ZoneAnswerKind.Answer, result.Kind);
        Assert.NotNull(result.Message);
        Assert.True(result.Message!.Flags.Authoritative);
        Assert.Contains(result.Message.Records.Answers, r =>
            r.Type == DomainRecordType.A &&
            ((IPAddressData)r.Data).Address.Equals(IPAddress.Parse("192.0.2.10")));
    }

    [Fact]
    public void AnswerEngine_ReferralBelowNsCut()
    {
        var zone = BuildZone(FooBarZone, "foo.bar.bind");
        var request = DomainMessage.CreateRequest("host.child.foo.bar");
        var result = ZoneAnswerEngine.Answer(zone, request);

        Assert.Equal(ZoneAnswerKind.Referral, result.Kind);
        Assert.NotNull(result.Message);
        Assert.False(result.Message!.Flags.Authoritative);
        Assert.Empty(result.Message.Records.Answers);
        Assert.Contains(result.Message.Records.Authorities, r => r.Type == DomainRecordType.NS);
        Assert.Contains(result.Message.Records.Additional, r =>
            r.Type == DomainRecordType.A &&
            ((IPAddressData)r.Data).Address.Equals(IPAddress.Parse("192.0.2.50")));
        Assert.Equal("child.foo.bar", result.ReferralCutApex);
    }

    [Fact]
    public void AnswerEngine_WildcardSynthesizesOwnerAsQname()
    {
        var zone = BuildZone(FooBarZone, "foo.bar.bind");
        var request = DomainMessage.CreateRequest("random.foo.bar");
        var result = ZoneAnswerEngine.Answer(zone, request);

        Assert.Equal(ZoneAnswerKind.Answer, result.Kind);
        var answer = Assert.Single(result.Message!.Records.Answers);
        Assert.Equal("random.foo.bar", answer.Name.ToString());
        Assert.Equal(IPAddress.Parse("192.0.2.99"), ((IPAddressData)answer.Data).Address);
    }

    [Fact]
    public void AnswerEngine_ExactNameBlocksWildcard()
    {
        var text = """
            $ORIGIN foo.bar.
            $TTL 3600
            @ IN SOA ns.foo.bar. hostmaster.foo.bar. ( 1 7200 3600 1209600 3600 )
            @ IN NS ns.foo.bar.
            www IN TXT "exact"
            * IN A 192.0.2.99
            """;
        var zone = BuildZone(text, "foo.bar.bind");
        var request = DomainMessage.CreateRequest("www.foo.bar");
        var result = ZoneAnswerEngine.Answer(zone, request);

        Assert.Equal(ZoneAnswerKind.NoData, result.Kind);
        Assert.Empty(result.Message!.Records.Answers);
        Assert.Equal(DomainResponseCode.NoError, result.Message.Flags.ResponseCode);
    }

    [Fact]
    public void AnswerEngine_WildcardDoesNotCrossNsCut()
    {
        var zone = BuildZone(FooBarZone, "foo.bar.bind");
        var request = DomainMessage.CreateRequest("nope.child.foo.bar");
        var result = ZoneAnswerEngine.Answer(zone, request);

        Assert.Equal(ZoneAnswerKind.Referral, result.Kind);
    }

    [Fact]
    public void ParseFile_SupportsInclude()
    {
        var dir = Path.Combine(Path.GetTempPath(), "dhcpr-zone-" + Guid.NewGuid().ToString("n"));
        Directory.CreateDirectory(dir);
        try
        {
            File.WriteAllText(Path.Combine(dir, "hosts.bind"), """
                $TTL 3600
                www.example.com. IN A 192.0.2.10
                """);
            var main = Path.Combine(dir, "example.bind");
            File.WriteAllText(main, """
                $ORIGIN example.com.
                $TTL 3600
                @ IN SOA ns.example.com. host.example.com. ( 1 7200 3600 1209600 3600 )
                @ IN NS ns.example.com.
                ns IN A 192.0.2.1
                $INCLUDE hosts.bind
                """);

            var records = ZoneFileParser.ParseFile(main);
            Assert.Contains(records, r =>
                r.Type == DomainRecordType.A &&
                r.Name.ToString().Equals("www.example.com", StringComparison.OrdinalIgnoreCase));
        }
        finally
        {
            Directory.Delete(dir, recursive: true);
        }
    }

    [Fact]
    public async Task Recursive_StartsAtLocalZone_NoRootQuery()
    {
        var store = new AuthoritativeZoneStore();
        store.Publish([BuildZone(FooBarZone, "foo.bar.bind")]);

        var client = new CountingInternalClient(_ => throw new InvalidOperationException("should not query upstream"));
        var resolver = CreateResolver(client, store);
        var request = DomainMessage.CreateRequest("www.foo.bar");
        var context = new DomainMessageContext(null, null, request);

        var result = await resolver.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.True(context.DoNotCacheResponse);
        Assert.True(result!.Flags.Authoritative);
        Assert.Empty(client.Queries);
    }

    [Fact]
    public async Task Recursive_ReferralFollowsChildNs()
    {
        var childNs = new IPEndPoint(IPAddress.Parse("192.0.2.50"), 53);
        var store = new AuthoritativeZoneStore();
        store.Publish([BuildZone(FooBarZone, "foo.bar.bind")]);

        var client = new CountingInternalClient(request =>
        {
            if (request.Questions[0].Name.ToString()
                    .Equals("host.child.foo.bar", StringComparison.OrdinalIgnoreCase) &&
                request.Questions[0].Type == DomainRecordType.A)
            {
                return DomainMessage.CreateResponse(
                    request,
                    answers:
                    [
                        new DomainResourceRecord(
                            request.Questions[0].Name,
                            DomainRecordType.A,
                            DomainRecordClass.IN,
                            TimeSpan.FromSeconds(60),
                            new IPAddressData(IPAddress.Parse("192.0.2.77")))
                    ],
                    responseCode: DomainResponseCode.NoError);
            }

            return DomainMessage.CreateResponse(request, DomainResourceRecords.Empty, DomainResponseCode.ServerFailure);
        });

        var resolver = CreateResolver(client, store);
        var request = DomainMessage.CreateRequest("host.child.foo.bar");
        var context = new DomainMessageContext(null, null, request);

        var result = await resolver.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Contains(result!.Records.Answers, r =>
            r.Type == DomainRecordType.A &&
            ((IPAddressData)r.Data).Address.Equals(IPAddress.Parse("192.0.2.77")));
        Assert.Contains(client.UpstreamEndPoints, ep => ep.Address.Equals(childNs.Address));
        Assert.DoesNotContain(client.Queries, q => q.StartsWith("bar/", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task Recursive_ChildZoneAtCut_AnswersLocallyWithoutParentLoop()
    {
        var parent = BuildZone(FooBarZone, "foo.bar.bind");
        var child = BuildZone("""
            $ORIGIN child.foo.bar.
            $TTL 3600
            @ IN SOA ns.child.foo.bar. host.child.foo.bar. ( 1 7200 3600 1209600 3600 )
            @ IN NS ns.child.foo.bar.
            ns IN A 192.0.2.50
            host IN A 192.0.2.88
            """, "child.foo.bar.bind");

        var store = new AuthoritativeZoneStore();
        store.Publish([parent, child]);

        var client = new CountingInternalClient(_ => throw new InvalidOperationException("no upstream"));
        var resolver = CreateResolver(client, store);
        var request = DomainMessage.CreateRequest("host.child.foo.bar");
        var context = new DomainMessageContext(null, null, request);

        var result = await resolver.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.True(context.DoNotCacheResponse);
        Assert.Contains(result!.Records.Answers, r =>
            ((IPAddressData)r.Data).Address.Equals(IPAddress.Parse("192.0.2.88")));
        Assert.Empty(client.Queries);
    }

    [Fact]
    public async Task Forward_DefersWhenLocalZoneMatches()
    {
        var store = new AuthoritativeZoneStore();
        store.Publish([BuildZone(FooBarZone, "foo.bar.bind")]);

        var configuration = new DnsConfiguration
        {
            RootServers = new RootServerConfiguration { Addresses = ["198.41.0.4:53"] },
            Routes = new Dictionary<string, string[]>
            {
                ["foo.bar"] = ["10.0.0.1:53"]
            },
            ListenAddresses = ["udp://127.0.0.1:5353"]
        };
        Assert.True(configuration.Validate());

        var forwarded = false;
        var client = new CountingInternalClient((_, _) =>
        {
            forwarded = true;
            return DomainMessage.CreateResponse(
                DomainMessage.CreateRequest("www.foo.bar"),
                DomainResourceRecords.Empty,
                DomainResponseCode.ServerFailure);
        });

        var forwarder = new ForwardResolver(
            new StaticOptionsMonitor<DnsConfiguration>(configuration),
            client,
            store,
            NullLogger<ForwardResolver>.Instance);

        var result = await forwarder.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("www.foo.bar")),
            CancellationToken.None);

        Assert.Null(result);
        Assert.False(forwarded);
    }

    [Fact]
    public async Task CacheDecorator_SkipsSetWhenDoNotCache()
    {
        var memory = new MemoryCache(new MemoryCacheOptions { SizeLimit = 1000 });
        var cache = new DnsResponseCache(memory);
        var inner = new FixedMiddleware(Priority: 1, (ctx, msg) =>
        {
            ctx.DoNotCacheResponse = true;
            return DomainMessage.CreateResponse(
                msg,
                answers:
                [
                    new DomainResourceRecord(
                        msg.Questions[0].Name,
                        DomainRecordType.A,
                        DomainRecordClass.IN,
                        TimeSpan.FromSeconds(300),
                        new IPAddressData(IPAddress.Parse("192.0.2.1")))
                ],
                responseCode: DomainResponseCode.NoError);
        });

        var decorator = new CacheResolverDecorator(inner, cache);
        var request = DomainMessage.CreateRequest("www.foo.bar");
        var context = new DomainMessageContext(null, null, request);

        Assert.NotNull(await decorator.ProcessAsync(context, CancellationToken.None));
        Assert.False(cache.TryGet(request, out _));
    }

    [Fact]
    public void Cache_ClearRemovesEntries()
    {
        var memory = new MemoryCache(new MemoryCacheOptions { SizeLimit = 1000 });
        var cache = new DnsResponseCache(memory);
        var request = DomainMessage.CreateRequest("www.example.com");
        var response = DomainMessage.CreateResponse(
            request,
            answers:
            [
                new DomainResourceRecord(
                    request.Questions[0].Name,
                    DomainRecordType.A,
                    DomainRecordClass.IN,
                    TimeSpan.FromSeconds(300),
                    new IPAddressData(IPAddress.Parse("192.0.2.1")))
            ],
            responseCode: DomainResponseCode.NoError);
        cache.Set(request, response);
        Assert.True(cache.TryGet(request, out _));
        cache.Clear();
        Assert.False(cache.TryGet(request, out _));
    }

    private static AuthoritativeZone BuildZone(string text, string path)
    {
        var records = ZoneFileParser.Parse(text);
        return AuthoritativeZoneBuilder.FromRecords(records, path);
    }

    private static RecursiveRootResolver CreateResolver(
        IInternalDomainClient client,
        AuthoritativeZoneStore store)
    {
        var tips = new RootServerTips(new StaticOptionsMonitor<RootServerConfiguration>(
            new RootServerConfiguration { Addresses = ["198.41.0.4:53"] }));
        return new RecursiveRootResolver(
            tips,
            client,
            store,
            DynamicDnsTestHelpers.CreateStore(),
            NullLogger<RecursiveRootResolver>.Instance);
    }

    private sealed class StaticOptionsMonitor<T> : IOptionsMonitor<T>
    {
        public StaticOptionsMonitor(T current) => CurrentValue = current;
        public T CurrentValue { get; }
        public T Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }

    private sealed class FixedMiddleware : IDomainMessageMiddleware
    {
        private readonly Func<DomainMessageContext, DomainMessage, DomainMessage> _handler;
        public FixedMiddleware(int Priority, Func<DomainMessageContext, DomainMessage, DomainMessage> handler)
        {
            this.Priority = Priority;
            _handler = handler;
        }

        public int Priority { get; }
        public string Name => "Fixed";
        public ValueTask<DomainMessage?> ProcessAsync(DomainMessageContext context, CancellationToken cancellationToken)
            => ValueTask.FromResult<DomainMessage?>(_handler(context, context.DomainMessage));
    }

    private sealed class CountingInternalClient : IInternalDomainClient
    {
        private readonly Func<DomainMessage, ImmutableArray<IPEndPoint>, DomainMessage> _handler;

        public CountingInternalClient(Func<DomainMessage, DomainMessage> handler)
            : this((m, _) => handler(m))
        {
        }

        public CountingInternalClient(Func<DomainMessage, ImmutableArray<IPEndPoint>, DomainMessage> handler)
        {
            _handler = handler;
        }

        public List<string> Queries { get; } = [];
        public List<IPEndPoint> UpstreamEndPoints { get; } = [];

        public ValueTask<DomainMessage> SendAsync(DomainMessage message, CancellationToken cancellationToken)
            => SendAsync(new DomainMessageContext(null, null, message) { IsInternal = true }, message, default, cancellationToken);

        public ValueTask<DomainMessage> SendAsync(
            DomainMessageContext parentContext,
            DomainMessage message,
            CancellationToken cancellationToken)
            => SendAsync(parentContext, message, default, cancellationToken);

        public ValueTask<DomainMessage> SendAsync(
            DomainMessageContext parentContext,
            DomainMessage message,
            ImmutableArray<IPEndPoint> upstreamEndpoints,
            CancellationToken cancellationToken)
        {
            Queries.Add($"{message.Questions[0].Name}/{message.Questions[0].Type}");
            if (!upstreamEndpoints.IsDefaultOrEmpty)
                UpstreamEndPoints.AddRange(upstreamEndpoints);
            return ValueTask.FromResult(_handler(message, upstreamEndpoints));
        }
    }
}
