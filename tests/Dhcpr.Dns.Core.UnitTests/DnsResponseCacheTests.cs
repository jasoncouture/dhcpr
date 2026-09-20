using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Resolvers.Caching;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

using Microsoft.Extensions.Caching.Memory;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class DnsResponseCacheTests
{
    [Fact]
    public void CacheHitReturnsRecordsWithTtlDecrementedByCacheAge()
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
        // Immediate hit: TTL should still be at/near the stored value.
        Assert.True(cached.Records.Answers[0].TimeToLive <= TimeSpan.FromSeconds(300));
        Assert.True(cached.Records.Answers[0].TimeToLive > TimeSpan.FromSeconds(290));
    }

    [Fact]
    public void PolicyResponseTtlIsOneHour()
        => Assert.Equal(TimeSpan.FromHours(1), DnsResponseCache.PolicyResponseTtl);

    [Theory]
    [InlineData(DomainResponseCode.NotImplemented)]
    [InlineData(DomainResponseCode.Refused)]
    public void EmptyPolicyAnswersAreCached(DomainResponseCode rcode)
    {
        var cache = CreateCache();
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.ANY);
        var response = DomainMessage.CreateResponse(request, DomainResourceRecords.Empty, rcode);

        cache.Set(request, response);

        Assert.True(cache.TryGet(request, out var cached));
        Assert.NotNull(cached);
        Assert.Equal(rcode, cached!.Flags.ResponseCode);
        Assert.Empty(cached.Records.Answers);
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
    public void DoesNotCacheNsReferral()
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

        Assert.False(cache.TryGet(request, out _));
        Assert.False(cache.TryGet(DomainMessage.CreateRequest("a.gtld-servers.net", DomainRecordType.A), out _));
    }

    [Fact]
    public void CachesAuthoritativeNsAnswerAndGlue()
    {
        var cache = CreateCache();
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.NS);
        var glueAddress = IPAddress.Parse("192.0.2.53");
        var response = new DomainMessage(
            request.Id,
            new DomainMessageFlags(true, DomainOperationCode.Query, true, false, false, false, false, false,
                DomainResponseCode.NoError),
            request.Questions,
            new DomainResourceRecords(
                System.Collections.Immutable.ImmutableArray.Create(
                    new DomainResourceRecord(
                        new DomainLabels("example.com"),
                        DomainRecordType.NS,
                        DomainRecordClass.IN,
                        TimeSpan.FromSeconds(300),
                        new NameData(new DomainLabels("ns.example.com")))),
                System.Collections.Immutable.ImmutableArray<DomainResourceRecord>.Empty,
                System.Collections.Immutable.ImmutableArray.Create(
                    new DomainResourceRecord(
                        new DomainLabels("ns.example.com"),
                        DomainRecordType.A,
                        DomainRecordClass.IN,
                        TimeSpan.FromSeconds(300),
                        new IPAddressData(glueAddress)))));

        cache.Set(request, response);

        Assert.True(cache.TryGet(request, out var cachedNs));
        Assert.NotNull(cachedNs);
        Assert.Contains(cachedNs!.Records.Answers, r => r.Type == DomainRecordType.NS);

        var glueLookup = DomainMessage.CreateRequest("ns.example.com", DomainRecordType.A);
        Assert.True(cache.TryGet(glueLookup, out var cachedGlue));
        Assert.NotNull(cachedGlue);
        Assert.Equal(glueAddress, ((IPAddressData)cachedGlue!.Records.Answers[0].Data).Address);
    }

    [Theory]
    [InlineData(80, 0, false)]
    [InlineData(80, 69, false)]
    [InlineData(80, 70, false)]
    [InlineData(80, 71, true)]
    public void ShouldRefreshWhenLessThanOneEighthRemains(int lifetimeSeconds, int ageSeconds, bool expected)
        => Assert.Equal(
            expected,
            DnsResponseCache.ShouldRefresh(TimeSpan.FromSeconds(lifetimeSeconds), TimeSpan.FromSeconds(ageSeconds)));

    [Fact]
    public void TryGetFlagsRefreshWhenImportIsPastSevenEighths()
    {
        var cache = CreateCache();
        var request = DomainMessage.CreateRequest("stale.example", DomainRecordType.A);
        var response = AddressResponse(request, "203.0.113.9");
        cache.Import(
            request,
            response,
            DnssecValidationStatus.Unchecked,
            DateTimeOffset.UtcNow - TimeSpan.FromSeconds(270));

        Assert.True(cache.TryGet(request, out var cached, out _, out var shouldRefresh));
        Assert.NotNull(cached);
        Assert.True(shouldRefresh);
    }

    [Fact]
    public void FreshSetDoesNotAskForRefresh()
    {
        var cache = CreateCache();
        var request = DomainMessage.CreateRequest("fresh.example", DomainRecordType.A);
        cache.Set(request, AddressResponse(request, "203.0.113.10"));

        Assert.True(cache.TryGet(request, out _, out _, out var shouldRefresh));
        Assert.False(shouldRefresh);
    }

    [Fact]
    public async Task DecoratorRefreshesInBackgroundWithoutBlockingTheHit()
    {
        var cache = CreateCache();
        var request = DomainMessage.CreateRequest("hot.example", DomainRecordType.A);
        cache.Import(
            request,
            AddressResponse(request, "203.0.113.11"),
            DnssecValidationStatus.Unchecked,
            DateTimeOffset.UtcNow - TimeSpan.FromSeconds(270));

        var started = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        var finish = new TaskCompletionSource<DomainMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        var client = Substitute.For<IInternalDomainClient>();
        client.SendRefreshAsync(
                Arg.Any<DomainMessageContext>(),
                Arg.Any<DomainMessage>(),
                Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                started.TrySetResult();
                return new ValueTask<DomainMessage>(finish.Task);
            });

        var inner = Substitute.For<IDomainMessageMiddleware>();
        IDomainMessageMiddleware decorator = new CacheResolverDecorator(inner, cache, client, logger: null);
        var context = new DomainMessageContext(null, null, request);

        var hit = await decorator.ProcessAsync(context, CancellationToken.None);

        Assert.True(context.CacheHit);
        Assert.Equal("Cache", context.AnsweredBy);
        Assert.Equal(IPAddress.Parse("203.0.113.11"), ((IPAddressData)hit!.Records.Answers[0].Data).Address);
        await inner.DidNotReceive().ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
        await started.Task.WaitAsync(TimeSpan.FromSeconds(2));

        var refreshed = AddressResponse(request, "203.0.113.12");
        finish.TrySetResult(refreshed);
        DomainMessage? after = null;
        var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(2);
        var shouldRefresh = true;
        while (DateTime.UtcNow < deadline)
        {
            if (cache.TryGet(request, out after, out _, out shouldRefresh) &&
                after?.Records.Answers is [{ Data: IPAddressData ip }] &&
                ip.Address.Equals(IPAddress.Parse("203.0.113.12")))
                break;
            await Task.Delay(10);
        }

        Assert.False(shouldRefresh);
        Assert.Equal(IPAddress.Parse("203.0.113.12"), ((IPAddressData)after!.Records.Answers[0].Data).Address);
    }

    [Fact]
    public async Task DecoratorServesCachedResponseWithoutCallingInner()
    {
        var cache = CreateCache();
        var address = IPAddress.Parse("1.2.3.4");
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                var context = callInfo.ArgAt<DomainMessageContext>(0);
                return new ValueTask<DomainMessage>(DomainMessage.CreateResponse(
                    context.DomainMessage,
                    new[]
                    {
                        new DomainResourceRecord(
                            new DomainLabels("cached.example"),
                            DomainRecordType.A,
                            DomainRecordClass.IN,
                            TimeSpan.FromSeconds(120),
                            new IPAddressData(address))
                    },
                    responseCode: DomainResponseCode.NoError));
            });

        IDomainMessageMiddleware decorator = new CacheResolverDecorator(inner, cache);
        var request = DomainMessage.CreateRequest("cached.example", DomainRecordType.A);
        var context = new DomainMessageContext(null, null, request);

        var first = await decorator.ProcessAsync(context, CancellationToken.None);
        Assert.Null(context.AnsweredBy);

        var second = await decorator.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(first);
        Assert.NotNull(second);
        Assert.True(context.CacheHit);
        Assert.Equal("Cache", context.AnsweredBy);
        await inner.Received(1).ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
        Assert.Equal(address, ((IPAddressData)second!.Records.Answers[0].Data).Address);
    }

    [Fact]
    public async Task CacheDecorator_BypassCacheSkipsLookupAndStore()
    {
        var cache = CreateCache();
        var address = IPAddress.Parse("203.0.113.10");
        var request = DomainMessage.CreateRequest("bypass.example", DomainRecordType.A);
        var response = DomainMessage.CreateResponse(
            request,
            new[]
            {
                new DomainResourceRecord(
                    new DomainLabels("bypass.example"),
                    DomainRecordType.A,
                    DomainRecordClass.IN,
                    TimeSpan.FromSeconds(120),
                    new IPAddressData(address))
            },
            responseCode: DomainResponseCode.NoError);
        cache.Set(request, response);

        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage>(response));

        IDomainMessageMiddleware decorator = new CacheResolverDecorator(inner, cache);
        var context = new DomainMessageContext(null, null, request) { BypassCache = true };

        var result = await decorator.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.False(context.CacheHit);
        await inner.Received(1).ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public void SetPublishesOnceImportDoesNot()
    {
        var publisher = new RecordingCachePublisher();
        var cache = CreateCache(publisher);
        var request = DomainMessage.CreateRequest("pub.example", DomainRecordType.A);
        var response = AddressResponse(request, "203.0.113.8");

        cache.Set(request, response);
        Assert.Equal(1, publisher.Sets);

        cache.Import(request, response, DnssecValidationStatus.Secure, DateTimeOffset.UtcNow);
        Assert.Equal(1, publisher.Sets);
        Assert.Equal(0, publisher.Clears);
    }

    [Fact]
    public void ImportAppliesReplicaPayload()
    {
        var source = CreateCache();
        var replica = CreateCache();
        var request = DomainMessage.CreateRequest("replica.example", DomainRecordType.A);
        var response = AddressResponse(request, "198.51.100.4");
        var cachedAt = DateTimeOffset.UtcNow;

        source.Set(request, response);
        replica.Import(request, response, DnssecValidationStatus.Unchecked, cachedAt);

        Assert.True(replica.TryGet(request, out var cached, out var status));
        Assert.Equal(IPAddress.Parse("198.51.100.4"), ((IPAddressData)cached!.Records.Answers[0].Data).Address);
        Assert.Equal(DnssecValidationStatus.Unchecked, status);
    }

    [Fact]
    public void ImportClearEmptiesWithoutPublishing()
    {
        var publisher = new RecordingCachePublisher();
        var cache = CreateCache(publisher);
        var request = DomainMessage.CreateRequest("wipe.example", DomainRecordType.A);
        cache.Set(request, AddressResponse(request, "192.0.2.9"));
        publisher.Sets = 0;

        cache.ImportClear();

        Assert.False(cache.TryGet(request, out _));
        Assert.Equal(0, publisher.Clears);

        cache.Clear();
        Assert.Equal(1, publisher.Clears);
    }

    [Fact]
    public void ImportSecurityStatusDoesNotPublish()
    {
        var publisher = new RecordingCachePublisher();
        var cache = CreateCache(publisher);
        var request = DomainMessage.CreateRequest("sec.example", DomainRecordType.A);
        cache.Set(request, AddressResponse(request, "192.0.2.10"));

        cache.ImportSecurityStatus(request, DnssecValidationStatus.Secure);
        Assert.Equal(0, publisher.Statuses);

        Assert.True(cache.TryGet(request, out _, out var status));
        Assert.Equal(DnssecValidationStatus.Secure, status);

        cache.UpdateSecurityStatus(request, DnssecValidationStatus.Insecure);
        Assert.Equal(1, publisher.Statuses);
    }

    private static DomainMessage AddressResponse(DomainMessage request, string ip)
        => DomainMessage.CreateResponse(
            request,
            new[]
            {
                new DomainResourceRecord(
                    request.Questions[0].Name,
                    DomainRecordType.A,
                    DomainRecordClass.IN,
                    TimeSpan.FromSeconds(300),
                    new IPAddressData(IPAddress.Parse(ip)))
            },
            responseCode: DomainResponseCode.NoError);

    private static DnsResponseCache CreateCache(IDnsCacheEventPublisher? publisher = null)
        => new(new MemoryCache(new MemoryCacheOptions { SizeLimit = 10_000 }), publisher);

    private sealed class RecordingCachePublisher : IDnsCacheEventPublisher
    {
        public Guid OriginId { get; } = Guid.NewGuid();
        public int Sets;
        public int Statuses;
        public int Clears;

        public void PublishSet(
            DomainMessage request,
            DomainMessage response,
            DnssecValidationStatus securityStatus,
            DateTimeOffset cachedAt)
            => Sets++;

        public void PublishSecurityStatus(DomainMessage request, DnssecValidationStatus securityStatus)
            => Statuses++;

        public void PublishClear() => Clears++;
    }
}
