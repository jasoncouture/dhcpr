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

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

using NSubstitute;

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
    public void AnswerEngine_CnameOwnerReturnsCnameForOtherTypes()
    {
        var text = """
            $ORIGIN foo.bar.
            $TTL 3600
            @ IN SOA ns.foo.bar. hostmaster.foo.bar. ( 1 7200 3600 1209600 3600 )
            @ IN NS ns.foo.bar.
            alias IN CNAME www.foo.bar.
            www IN A 192.0.2.10
            """;
        var zone = BuildZone(text, "foo.bar.bind");
        var request = DomainMessage.CreateRequest("alias.foo.bar");
        var result = ZoneAnswerEngine.Answer(zone, request);

        Assert.Equal(ZoneAnswerKind.Answer, result.Kind);
        var answer = Assert.Single(result.Message!.Records.Answers);
        Assert.Equal(DomainRecordType.CNAME, answer.Type);
        Assert.Equal("www.foo.bar", ((NameData)answer.Data).Name.ToString());
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
    public async Task Authoritative_StartsAtLocalZone_NoRootQuery()
    {
        var store = new AuthoritativeZoneStore();
        store.Publish([BuildZone(FooBarZone, "foo.bar.bind")]);

        var middleware = CreateAuthoritative(store);
        var request = DomainMessage.CreateRequest("www.foo.bar");
        var context = new DomainMessageContext(null, null, request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.True(context.DoNotCacheResponse);
        Assert.Equal("Authoritative Zones", context.AnsweredBy);
        Assert.True(result!.Flags.Authoritative);
    }

    [Fact]
    public async Task Authoritative_MissCallsInner()
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var request = DomainMessage.CreateRequest("www.example.com");
        var passed = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(passed);

        var middleware = new AuthoritativeZoneMiddleware(inner, new AuthoritativeZoneStore());
        var result = await middleware.ProcessAsync(
            new DomainMessageContext(null, null, request),
            CancellationToken.None);

        Assert.Same(passed, result);
        await inner.Received(1)
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authoritative_ReferralFollowsChildNs()
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

        var middleware = CreateAuthoritativeNsCut(client.Client, store);
        var request = DomainMessage.CreateRequest("host.child.foo.bar");
        var context = new DomainMessageContext(null, null, request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Contains(result!.Records.Answers, r =>
            r.Type == DomainRecordType.A &&
            ((IPAddressData)r.Data).Address.Equals(IPAddress.Parse("192.0.2.77")));
        Assert.Contains(client.UpstreamEndPoints, ep => ep.Address.Equals(childNs.Address));
        Assert.DoesNotContain(client.Queries, q => q.StartsWith("bar/", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task AuthoritativeNsCut_MissCallsInner()
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var request = DomainMessage.CreateRequest("www.example.com");
        var passed = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(passed);

        var middleware = new AuthoritativeNsCutMiddleware(
            inner,
            new AuthoritativeZoneStore(),
            new ReferralWalker(Substitute.For<IInternalDomainClient>()));
        var result = await middleware.ProcessAsync(
            new DomainMessageContext(null, null, request),
            CancellationToken.None);

        Assert.Same(passed, result);
        await inner.Received(1)
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Authoritative_ChildZoneAtCut_AnswersLocallyWithoutParentLoop()
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

        var middleware = CreateAuthoritative(store);
        var request = DomainMessage.CreateRequest("host.child.foo.bar");
        var context = new DomainMessageContext(null, null, request);

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.True(context.DoNotCacheResponse);
        Assert.Contains(result!.Records.Answers, r =>
            ((IPAddressData)r.Data).Address.Equals(IPAddress.Parse("192.0.2.88")));
    }

    [Fact]
    public async Task Forward_DefersWhenLocalZoneMatches()
    {
        var store = new AuthoritativeZoneStore();
        store.Publish([BuildZone(FooBarZone, "foo.bar.bind")]);

        var configuration = new DnsConfiguration
        {
            RootServers = new RootServerConfiguration { Addresses = ["198.41.0.4:53"] },
            Routes = new Dictionary<string, DnsRouteConfiguration>
            {
                ["foo.bar"] = new() { Upstreams = ["10.0.0.1:53"] }
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
            PassThroughInner(),
            Monitor(configuration),
            client.Client,
            store);

        var result = await forwarder.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("www.foo.bar")),
            CancellationToken.None);

        Assert.Equal(DomainResponseCode.ServerFailure, result.Flags.ResponseCode);
        Assert.False(forwarded);
    }

    [Fact]
    public async Task CacheDecorator_SkipsSetWhenDoNotCache()
    {
        var memory = new MemoryCache(new MemoryCacheOptions { SizeLimit = 1000 });
        var cache = new DnsResponseCache(memory);
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.Priority.Returns(1);
        inner.Name.Returns("Fixed");
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(ci =>
            {
                var ctx = ci.Arg<DomainMessageContext>();
                ctx.DoNotCacheResponse = true;
                var msg = ctx.DomainMessage;
                return new ValueTask<DomainMessage>(DomainMessage.CreateResponse(
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
                    responseCode: DomainResponseCode.NoError));
            });

        IDomainMessageMiddleware decorator = new CacheResolverDecorator(inner, cache, Substitute.For<IServiceScopeFactory>());
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

    private static AuthoritativeZoneMiddleware CreateAuthoritative(AuthoritativeZoneStore store)
        => new(PassThroughInner(), store);

    private static AuthoritativeNsCutMiddleware CreateAuthoritativeNsCut(
        IInternalDomainClient client,
        AuthoritativeZoneStore store)
        => new(PassThroughInner(), store, new ReferralWalker(client));

    private static IDomainMessageMiddleware PassThroughInner()
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(call => DomainMessage.CreateResponse(
                call.Arg<DomainMessageContext>().DomainMessage,
                DomainResourceRecords.Empty,
                DomainResponseCode.ServerFailure));
        return inner;
    }

    private static IOptionsMonitor<T> Monitor<T>(T value)
    {
        var monitor = Substitute.For<IOptionsMonitor<T>>();
        monitor.CurrentValue.Returns(value);
        monitor.Get(Arg.Any<string?>()).Returns(value);
        return monitor;
    }

    private sealed class CountingInternalClient
    {
        public IInternalDomainClient Client { get; }
        public List<string> Queries { get; } = [];
        public List<IPEndPoint> UpstreamEndPoints { get; } = [];

        public CountingInternalClient(Func<DomainMessage, DomainMessage> handler)
            : this((m, _) => handler.Invoke(m))
        {
        }

        public CountingInternalClient(Func<DomainMessage, ImmutableArray<IPEndPoint>, DomainMessage> handler)
        {
            var client = Substitute.For<IInternalDomainClient>();

            ValueTask<DomainMessage> Send(DomainMessage message, ImmutableArray<IPEndPoint> upstreamEndpoints)
            {
                Queries.Add($"{message.Questions[0].Name}/{message.Questions[0].Type}");
                if (!upstreamEndpoints.IsDefaultOrEmpty)
                    UpstreamEndPoints.AddRange(upstreamEndpoints);
                return ValueTask.FromResult(handler.Invoke(message, upstreamEndpoints));
            }

            client.SendAsync(Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
                .Returns(ci => Send(ci.Arg<DomainMessage>(), default));
            client.SendAsync(Arg.Any<DomainMessageContext>(), Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
                .Returns(ci => Send(ci.ArgAt<DomainMessage>(1), default));
            client.SendAsync(
                    Arg.Any<DomainMessageContext>(),
                    Arg.Any<DomainMessage>(),
                    Arg.Any<ImmutableArray<IPEndPoint>>(),
                    Arg.Any<CancellationToken>())
                .Returns(ci => Send(ci.ArgAt<DomainMessage>(1), ci.ArgAt<ImmutableArray<IPEndPoint>>(2)));

            Client = client;
        }
    }
}
