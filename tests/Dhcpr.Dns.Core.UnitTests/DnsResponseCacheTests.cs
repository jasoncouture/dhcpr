using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Resolvers.Caching;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

using Microsoft.Extensions.Caching.Memory;

namespace Dhcpr.Dns.Core.UnitTests;

public class DnsResponseCacheTests
{
    [Fact]
    public void CacheHitReturnsStoredRecords()
    {
        var cache = CreateCache();
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.A);
        var address = IPAddress.Parse("93.184.216.34");
        var response = DomainMessage.CreateResponse(
            request,
            new[]
            {
                new DomainResourceRecord(
                    new DomainLabels("example.com"),
                    DomainRecordType.A,
                    DomainRecordClass.IN,
                    TimeSpan.FromSeconds(300),
                    new IPAddressData(address))
            },
            responseCode: DomainResponseCode.NoError);

        cache.Set(request, response);

        var lookup = DomainMessage.CreateRequest("example.com", DomainRecordType.A);
        Assert.True(cache.TryGet(lookup, out var cached));
        Assert.NotNull(cached);
        Assert.Equal(lookup.Id, cached!.Id);
        Assert.True(cached.Flags.RecursionAvailable);
        Assert.Single(cached.Records.Answers);
        Assert.Equal(address, ((IPAddressData)cached.Records.Answers[0].Data).Address);
        Assert.Equal(TimeSpan.FromSeconds(300), cached.Records.Answers[0].TimeToLive);
    }

    [Fact]
    public void DoesNotCacheServerFailure()
    {
        var cache = CreateCache();
        var request = DomainMessage.CreateRequest("broken.example", DomainRecordType.A);
        var response = DomainMessage.CreateResponse(request, DomainResourceRecords.Empty,
            DomainResponseCode.ServerFailure);

        cache.Set(request, response);

        Assert.False(cache.TryGet(request, out _));
    }

    [Fact]
    public void DoesNotCacheBareReferralForAddressQuery()
    {
        var cache = CreateCache();
        var request = DomainMessage.CreateRequest("google.com", DomainRecordType.A);
        var response = new DomainMessage(
            request.Id,
            new DomainMessageFlags(true, DomainOperationCode.Query, false, false, false, false, false, false,
                DomainResponseCode.NoError),
            request.Questions,
            new DomainResourceRecords(
                System.Collections.Immutable.ImmutableArray<DomainResourceRecord>.Empty,
                System.Collections.Immutable.ImmutableArray.Create(
                    new DomainResourceRecord(
                        new DomainLabels("google.com"),
                        DomainRecordType.NS,
                        DomainRecordClass.IN,
                        TimeSpan.FromSeconds(172800),
                        new NameData(new DomainLabels("ns1.google.com")))),
                System.Collections.Immutable.ImmutableArray.Create(
                    new DomainResourceRecord(
                        new DomainLabels("ns1.google.com"),
                        DomainRecordType.A,
                        DomainRecordClass.IN,
                        TimeSpan.FromSeconds(172800),
                        new IPAddressData(IPAddress.Parse("216.239.32.10"))))));

        cache.Set(request, response);

        Assert.False(cache.TryGet(request, out _));
    }

    [Fact]
    public void CachesNsDelegationAndGlue()
    {
        var cache = CreateCache();
        var request = DomainMessage.CreateRequest("com", DomainRecordType.NS);
        var glueAddress = IPAddress.Parse("192.5.6.30");
        var response = new DomainMessage(
            request.Id,
            new DomainMessageFlags(true, DomainOperationCode.Query, false, false, false, false, false, false,
                DomainResponseCode.NoError),
            request.Questions,
            new DomainResourceRecords(
                System.Collections.Immutable.ImmutableArray<DomainResourceRecord>.Empty,
                System.Collections.Immutable.ImmutableArray.Create(
                    new DomainResourceRecord(
                        new DomainLabels("com"),
                        DomainRecordType.NS,
                        DomainRecordClass.IN,
                        TimeSpan.FromSeconds(172800),
                        new NameData(new DomainLabels("a.gtld-servers.net")))),
                System.Collections.Immutable.ImmutableArray.Create(
                    new DomainResourceRecord(
                        new DomainLabels("a.gtld-servers.net"),
                        DomainRecordType.A,
                        DomainRecordClass.IN,
                        TimeSpan.FromSeconds(172800),
                        new IPAddressData(glueAddress)))));

        cache.Set(request, response);

        Assert.True(cache.TryGet(request, out var cachedNs));
        Assert.NotNull(cachedNs);
        Assert.Contains(cachedNs!.Records, r => r.Type == DomainRecordType.NS);

        var glueLookup = DomainMessage.CreateRequest("a.gtld-servers.net", DomainRecordType.A);
        Assert.True(cache.TryGet(glueLookup, out var cachedGlue));
        Assert.NotNull(cachedGlue);
        Assert.Equal(glueAddress, ((IPAddressData)cachedGlue!.Records.Answers[0].Data).Address);
    }

    [Fact]
    public async Task DecoratorServesCachedResponseWithoutCallingInner()
    {
        var cache = CreateCache();
        var calls = 0;
        var address = IPAddress.Parse("1.2.3.4");
        var inner = new StubMiddleware(request =>
        {
            calls++;
            return DomainMessage.CreateResponse(
                request,
                new[]
                {
                    new DomainResourceRecord(
                        new DomainLabels("cached.example"),
                        DomainRecordType.A,
                        DomainRecordClass.IN,
                        TimeSpan.FromSeconds(120),
                        new IPAddressData(address))
                },
                responseCode: DomainResponseCode.NoError);
        });

        var decorator = new CacheResolverDecorator(inner, cache);
        var request = DomainMessage.CreateRequest("cached.example", DomainRecordType.A);
        var context = new DomainMessageContext(null, null, request);

        var first = await decorator.ProcessAsync(context, CancellationToken.None);
        var second = await decorator.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(first);
        Assert.NotNull(second);
        Assert.Equal(1, calls);
        Assert.Equal(address, ((IPAddressData)second!.Records.Answers[0].Data).Address);
    }

    private static DnsResponseCache CreateCache()
        => new(new MemoryCache(new MemoryCacheOptions { SizeLimit = 10_000 }));

    private sealed class StubMiddleware : IDomainMessageMiddleware
    {
        private readonly Func<DomainMessage, DomainMessage> _handler;

        public StubMiddleware(Func<DomainMessage, DomainMessage> handler) => _handler = handler;

        public ValueTask<DomainMessage?> ProcessAsync(DomainMessageContext context, CancellationToken cancellationToken)
            => ValueTask.FromResult<DomainMessage?>(_handler(context.DomainMessage));

        public string Name => "stub";
        public int Priority => 0;
    }
}
