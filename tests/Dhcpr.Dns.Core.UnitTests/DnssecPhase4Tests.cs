using System.Collections.Immutable;
using System.Net;
using System.Security.Cryptography;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Resolvers.Caching;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;
using Dhcpr.Dns.Core.Validation;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class DnssecPhase4Tests
{
    [Fact]
    public void Cache_StripsAdAndRetainsRrsig()
    {
        var cache = CreateCache();
        var (dnsKey, privateKey) = CreateEcdsaDnsKey("example.com");
        var aRecord = new DomainResourceRecord(
            new DomainLabels("www.example.com"),
            DomainRecordType.A,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(300),
            new IPAddressData(IPAddress.Parse("192.0.2.10")));
        var rrsig = SignRrset(privateKey, dnsKey, [aRecord], DomainRecordType.A);

        var request = DomainMessage.CreateRequest("www.example.com");
        var response = DomainMessage.CreateResponse(
            request,
            answers: [aRecord, rrsig],
            responseCode: DomainResponseCode.NoError) with
        {
            Flags = DomainMessage.CreateResponse(request, answers: [aRecord], responseCode: DomainResponseCode.NoError)
                .Flags with { Authentic = true }
        };

        cache.Set(request, response, DnssecValidationStatus.Secure);

        Assert.True(cache.TryGet(request, out var cached, out var status));
        Assert.Equal(DnssecValidationStatus.Secure, status);
        Assert.False(cached!.Flags.Authentic);
        Assert.Contains(cached.Records.Answers, r => r.Type == DomainRecordType.RRSIG);
        Assert.Contains(cached.Records.Answers, r => r.Type == DomainRecordType.A);
    }

    [Fact]
    public void Cache_DoesNotStoreBogus()
    {
        var cache = CreateCache();
        var request = DomainMessage.CreateRequest("evil.example");
        var response = DomainMessage.CreateResponse(
            request,
            answers:
            [
                new DomainResourceRecord(
                    new DomainLabels("evil.example"),
                    DomainRecordType.A,
                    DomainRecordClass.IN,
                    TimeSpan.FromSeconds(60),
                    new IPAddressData(IPAddress.Parse("203.0.113.1")))
            ],
            responseCode: DomainResponseCode.NoError);

        cache.Set(request, response, DnssecValidationStatus.Bogus);
        Assert.False(cache.TryGet(request, out _));
    }

    [Fact]
    public void Cache_UpdateSecurityStatus_RemovesBogus()
    {
        var cache = CreateCache();
        var request = DomainMessage.CreateRequest("www.example.com");
        var response = DomainMessage.CreateResponse(
            request,
            answers:
            [
                new DomainResourceRecord(
                    new DomainLabels("www.example.com"),
                    DomainRecordType.A,
                    DomainRecordClass.IN,
                    TimeSpan.FromSeconds(60),
                    new IPAddressData(IPAddress.Parse("192.0.2.1")))
            ],
            responseCode: DomainResponseCode.NoError);

        cache.Set(request, response);
        cache.UpdateSecurityStatus(request, DnssecValidationStatus.Bogus);
        Assert.False(cache.TryGet(request, out _));
    }

    [Fact]
    public void Cache_StoresDnsKeyDsAndNsHopsWithRrsigs()
    {
        var cache = CreateCache();
        var (dnsKey, privateKey) = CreateEcdsaDnsKey("example.com");

        // DNSKEY hop
        var dnsKeyRequest = DomainMessage.CreateRequest("example.com", DomainRecordType.DNSKEY);
        var dnsKeySig = SignRrset(privateKey, dnsKey, [dnsKey], DomainRecordType.DNSKEY);
        cache.Set(
            dnsKeyRequest,
            DomainMessage.CreateResponse(dnsKeyRequest, answers: [dnsKey, dnsKeySig], responseCode: DomainResponseCode.NoError),
            DnssecValidationStatus.Secure);
        Assert.True(cache.TryGet(dnsKeyRequest, out var cachedKeys, out var keyStatus));
        Assert.Equal(DnssecValidationStatus.Secure, keyStatus);
        Assert.Contains(cachedKeys!.Records.Answers, r => r.Type == DomainRecordType.DNSKEY);
        Assert.Contains(cachedKeys.Records.Answers, r => r.Type == DomainRecordType.RRSIG);

        // DS hop
        var ds = new DomainResourceRecord(
            new DomainLabels("example.com"),
            DomainRecordType.DS,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(300),
            new DelegationSignerData(
                CalculateKeyTag(dnsKey),
                DnssecAlgorithmType.EcdsaP256Sha256,
                DelegationSignerDigestType.Sha256,
                Convert.FromHexString(ComputeDsDigestHex(dnsKey)).ToImmutableArray()));
        var dsRequest = DomainMessage.CreateRequest("example.com", DomainRecordType.DS);
        // Sign DS with parent key — use same key for unit-test storage check only.
        var dsSig = SignRrset(privateKey, dnsKey, [ds], DomainRecordType.DS);
        cache.Set(
            dsRequest,
            DomainMessage.CreateResponse(dsRequest, answers: [ds, dsSig], responseCode: DomainResponseCode.NoError),
            DnssecValidationStatus.Secure);
        Assert.True(cache.TryGet(dsRequest, out var cachedDs, out _));
        Assert.Contains(cachedDs!.Records.Answers, r => r.Type == DomainRecordType.DS);
        Assert.Contains(cachedDs.Records.Answers, r => r.Type == DomainRecordType.RRSIG);

        // NS hop (answers section)
        var ns = new DomainResourceRecord(
            new DomainLabels("example.com"),
            DomainRecordType.NS,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(300),
            new NameData(new DomainLabels("ns.example.com")));
        var nsSig = SignRrset(privateKey, dnsKey, [ns], DomainRecordType.NS);
        var nsRequest = DomainMessage.CreateRequest("example.com", DomainRecordType.NS);
        cache.Set(
            nsRequest,
            DomainMessage.CreateResponse(nsRequest, answers: [ns, nsSig], responseCode: DomainResponseCode.NoError),
            DnssecValidationStatus.Secure);
        Assert.True(cache.TryGet(nsRequest, out var cachedNs, out _));
        Assert.Contains(cachedNs!.Records.Answers, r => r.Type == DomainRecordType.NS);
        Assert.Contains(cachedNs.Records.Answers, r => r.Type == DomainRecordType.RRSIG);
    }

    [Fact]
    public async Task Middleware_CacheHitNeverServesAdFromFlagsAlone()
    {
        var cache = CreateCache();
        var request = DomainMessage.CreateRequest("www.example.com");
        var response = DomainMessage.CreateResponse(
            request,
            answers:
            [
                new DomainResourceRecord(
                    new DomainLabels("www.example.com"),
                    DomainRecordType.A,
                    DomainRecordClass.IN,
                    TimeSpan.FromSeconds(120),
                    new IPAddressData(IPAddress.Parse("192.0.2.10")))
            ],
            responseCode: DomainResponseCode.NoError) with
        {
            Flags = DomainMessage.CreateResponse(request, DomainResourceRecords.Empty, DomainResponseCode.NoError)
                .Flags with { Authentic = true, Response = true, ResponseCode = DomainResponseCode.NoError }
        };

        // Poison cache with AD=1 but Insecure status — middleware must not set AD.
        cache.Set(request, response, DnssecValidationStatus.Insecure);

        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(ci =>
            {
                var ctx = ci.ArgAt<DomainMessageContext>(0);
                Assert.True(cache.TryGet(ctx.DomainMessage, out var cached));
                Assert.NotNull(cached);
                ctx.CacheHit = true;
                ctx.CachedDnssecStatus = DnssecValidationStatus.Insecure;
                return new ValueTask<DomainMessage>(cached);
            });

        // Use real cache decorator path.
        IDomainMessageMiddleware cacheDecorator = new CacheResolverDecorator(Substitute.For<IDomainMessageMiddleware>(), cache);
        // Seed already done; second layer: dnssec around a hit-returning inner.
        var crypto = new DnssecValidator(NullLogger<DnssecValidator>.Instance, Monitor(new DnsConfiguration()));
        var options = Monitor(new DnsConfiguration
        {
            TrustAnchors = [new TrustAnchorConfiguration()]
        });
        var validator = new DnssecMessageValidator(
            crypto, NoopInternalClient(), options, NullLogger<DnssecMessageValidator>.Instance);
        var dnssec = new DnssecValidationMiddleware(
            inner, validator, cache, options, NullLogger<DnssecValidationMiddleware>.Instance);

        var scope = new DnssecScope();
        var context = new DomainMessageContext(null, null, request) { DnssecScope = scope };
        var result = await dnssec.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.False(result!.Flags.Authentic);
        Assert.Equal(DnssecValidationStatus.Insecure, scope.Status);
        _ = cacheDecorator;
    }

    [Fact]
    public async Task Middleware_CacheHitWithStoredStatusSkipsValidation()
    {
        var request = DomainMessage.CreateRequest("hit.example");
        var response = DomainMessage.CreateResponse(
            request,
            answers:
            [
                new DomainResourceRecord(
                    new DomainLabels("hit.example"),
                    DomainRecordType.A,
                    DomainRecordClass.IN,
                    TimeSpan.FromSeconds(60),
                    new IPAddressData(IPAddress.Parse("192.0.2.10")))
            ],
            responseCode: DomainResponseCode.NoError);

        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(ci =>
            {
                var ctx = ci.ArgAt<DomainMessageContext>(0);
                ctx.CacheHit = true;
                ctx.CachedDnssecStatus = DnssecValidationStatus.Secure;
                return new ValueTask<DomainMessage>(response);
            });

        var validator = Substitute.For<IDnssecMessageValidator>();
        var dnssec = new DnssecValidationMiddleware(
            inner,
            validator,
            Substitute.For<IDnsResponseCache>(),
            Monitor(new DnsConfiguration()),
            NullLogger<DnssecValidationMiddleware>.Instance);

        var scope = new DnssecScope();
        var context = new DomainMessageContext(null, null, request) { DnssecScope = scope };
        var result = await dnssec.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.True(result!.Flags.Authentic);
        Assert.Equal(DnssecValidationStatus.Secure, scope.Status);
        validator.DidNotReceive().EnsureTrustAnchorsLoaded(Arg.Any<DnssecScope>());
        await validator.DidNotReceive()
            .ValidateResponseAsync(
                Arg.Any<DomainMessageContext>(),
                Arg.Any<DomainMessage>(),
                Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task Middleware_CacheHitUncheckedStillValidates()
    {
        var request = DomainMessage.CreateRequest("legacy.example");
        var response = DomainMessage.CreateResponse(
            request,
            answers:
            [
                new DomainResourceRecord(
                    new DomainLabels("legacy.example"),
                    DomainRecordType.A,
                    DomainRecordClass.IN,
                    TimeSpan.FromSeconds(60),
                    new IPAddressData(IPAddress.Parse("192.0.2.11")))
            ],
            responseCode: DomainResponseCode.NoError);

        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(ci =>
            {
                var ctx = ci.ArgAt<DomainMessageContext>(0);
                ctx.CacheHit = true;
                ctx.CachedDnssecStatus = DnssecValidationStatus.Unchecked;
                return new ValueTask<DomainMessage>(response);
            });

        var validator = Substitute.For<IDnssecMessageValidator>();
        validator.ValidateResponseAsync(
                Arg.Any<DomainMessageContext>(),
                Arg.Any<DomainMessage>(),
                Arg.Any<CancellationToken>())
            .Returns(ci =>
            {
                ci.ArgAt<DomainMessageContext>(0).DnssecScope!.Observe(DnssecValidationStatus.Insecure);
                return ValueTask.CompletedTask;
            });

        var cache = Substitute.For<IDnsResponseCache>();
        var dnssec = new DnssecValidationMiddleware(
            inner,
            validator,
            cache,
            Monitor(new DnsConfiguration()),
            NullLogger<DnssecValidationMiddleware>.Instance);

        var scope = new DnssecScope();
        var context = new DomainMessageContext(null, null, request) { DnssecScope = scope };
        var result = await dnssec.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.False(result!.Flags.Authentic);
        Assert.Equal(DnssecValidationStatus.Insecure, scope.Status);
        validator.Received(1).EnsureTrustAnchorsLoaded(scope);
        await validator.Received(1)
            .ValidateResponseAsync(context, Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>());
        cache.Received(1).UpdateSecurityStatus(request, DnssecValidationStatus.Insecure);
    }

    [Fact]
    public async Task Middleware_UncheckedHitPersistsStatusSoNextHitSkipsValidation()
    {
        var cache = CreateCache();
        var request = DomainMessage.CreateRequest("legacy.example");
        var response = DomainMessage.CreateResponse(
            request,
            answers:
            [
                new DomainResourceRecord(
                    new DomainLabels("legacy.example"),
                    DomainRecordType.A,
                    DomainRecordClass.IN,
                    TimeSpan.FromSeconds(60),
                    new IPAddressData(IPAddress.Parse("192.0.2.11")))
            ],
            responseCode: DomainResponseCode.NoError);
        cache.Set(request, response);

        var leaf = Substitute.For<IDomainMessageMiddleware>();
        var validator = Substitute.For<IDnssecMessageValidator>();
        validator.ValidateResponseAsync(
                Arg.Any<DomainMessageContext>(),
                Arg.Any<DomainMessage>(),
                Arg.Any<CancellationToken>())
            .Returns(ci =>
            {
                ci.ArgAt<DomainMessageContext>(0).DnssecScope!.Observe(DnssecValidationStatus.Insecure);
                return ValueTask.CompletedTask;
            });

        var dnssec = new DnssecValidationMiddleware(
            new CacheResolverDecorator(leaf, cache),
            validator,
            cache,
            Monitor(new DnsConfiguration()),
            NullLogger<DnssecValidationMiddleware>.Instance);

        await dnssec.ProcessAsync(HitContext(request), CancellationToken.None);
        await dnssec.ProcessAsync(HitContext(request), CancellationToken.None);

        await validator.Received(1)
            .ValidateResponseAsync(
                Arg.Any<DomainMessageContext>(),
                Arg.Any<DomainMessage>(),
                Arg.Any<CancellationToken>());
        await leaf.DidNotReceive().ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
        Assert.True(cache.TryGet(request, out _, out var status));
        Assert.Equal(DnssecValidationStatus.Insecure, status);
    }

    private static DomainMessageContext HitContext(DomainMessage request)
        => new(null, null, request) { DnssecScope = new DnssecScope() };

    [Fact]
    public async Task Middleware_BypassCacheDoesNotUpdateSecurityStatus()
    {
        var cache = Substitute.For<IDnsResponseCache>();
        var request = DomainMessage.CreateRequest("health.example");
        var response = DomainMessage.CreateResponse(
            request,
            answers:
            [
                new DomainResourceRecord(
                    new DomainLabels("health.example"),
                    DomainRecordType.A,
                    DomainRecordClass.IN,
                    TimeSpan.FromSeconds(60),
                    new IPAddressData(IPAddress.Parse("192.0.2.80")))
            ],
            responseCode: DomainResponseCode.NoError);
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(response);

        var options = Monitor(new DnsConfiguration());
        var validator = new DnssecMessageValidator(
            new DnssecValidator(NullLogger<DnssecValidator>.Instance, options),
            NoopInternalClient(),
            options,
            NullLogger<DnssecMessageValidator>.Instance);
        var dnssec = new DnssecValidationMiddleware(
            inner, validator, cache, options, NullLogger<DnssecValidationMiddleware>.Instance);

        var context = new DomainMessageContext(null, null, request)
        {
            BypassCache = true,
            DnssecScope = new DnssecScope()
        };

        await dnssec.ProcessAsync(context, CancellationToken.None);

        cache.DidNotReceive()
            .UpdateSecurityStatus(Arg.Any<DomainMessage>(), Arg.Any<DnssecValidationStatus>());
    }

    [Fact]
    public async Task Middleware_MissUpdatesSecurityStatus()
    {
        var cache = Substitute.For<IDnsResponseCache>();
        var request = DomainMessage.CreateRequest("miss.example");
        var response = DomainMessage.CreateResponse(
            request,
            answers:
            [
                new DomainResourceRecord(
                    new DomainLabels("miss.example"),
                    DomainRecordType.A,
                    DomainRecordClass.IN,
                    TimeSpan.FromSeconds(60),
                    new IPAddressData(IPAddress.Parse("192.0.2.81")))
            ],
            responseCode: DomainResponseCode.NoError);
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(response);

        var options = Monitor(new DnsConfiguration());
        var validator = new DnssecMessageValidator(
            new DnssecValidator(NullLogger<DnssecValidator>.Instance, options),
            NoopInternalClient(),
            options,
            NullLogger<DnssecMessageValidator>.Instance);
        var dnssec = new DnssecValidationMiddleware(
            inner, validator, cache, options, NullLogger<DnssecValidationMiddleware>.Instance);

        var context = new DomainMessageContext(null, null, request)
        {
            DnssecScope = new DnssecScope()
        };

        await dnssec.ProcessAsync(context, CancellationToken.None);

        cache.Received(1)
            .UpdateSecurityStatus(request, Arg.Any<DnssecValidationStatus>());
    }

    [Fact]
    public async Task Cname_PreservesCoveringRrsigs()
    {
        var (dnsKey, privateKey) = CreateEcdsaDnsKey("example.com");
        var cname = new DomainResourceRecord(
            new DomainLabels("www.example.com"),
            DomainRecordType.CNAME,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(300),
            new NameData(new DomainLabels("target.example.com")));
        var cnameSig = SignRrset(privateKey, dnsKey, [cname], DomainRecordType.CNAME);
        var aRecord = new DomainResourceRecord(
            new DomainLabels("target.example.com"),
            DomainRecordType.A,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(300),
            new IPAddressData(IPAddress.Parse("192.0.2.55")));
        var aSig = SignRrset(privateKey, dnsKey, [aRecord], DomainRecordType.A);

        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(ci =>
            {
                var req = ci.ArgAt<DomainMessageContext>(0).DomainMessage;
                return new ValueTask<DomainMessage>(DomainMessage.CreateResponse(
                    req, answers: [cname, cnameSig], responseCode: DomainResponseCode.NoError));
            });

        var internalClient = Substitute.For<IInternalDomainClient>();
        internalClient
            .SendAsync(Arg.Any<DomainMessageContext>(), Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
            .Returns(ci =>
            {
                var req = ci.ArgAt<DomainMessage>(1);
                return new ValueTask<DomainMessage>(DomainMessage.CreateResponse(
                    req, answers: [aRecord, aSig], responseCode: DomainResponseCode.NoError));
            });

        IDomainMessageMiddleware decorator = new CanonicalNameResolverDecorator(inner, internalClient);
        var request = DomainMessage.CreateRequest("www.example.com");
        var result = await decorator.ProcessAsync(
            new DomainMessageContext(null, null, request), CancellationToken.None);

        Assert.NotNull(result);
        Assert.Contains(result!.Records.Answers, r => r.Type == DomainRecordType.CNAME);
        Assert.Contains(result.Records.Answers, r =>
            r.Type == DomainRecordType.RRSIG &&
            r.Data is ResourceRecordSignatureData sig &&
            sig.TypeCovered == DomainRecordType.CNAME);
        Assert.Contains(result.Records.Answers, r => r.Type == DomainRecordType.A);
        Assert.Contains(result.Records.Answers, r =>
            r.Type == DomainRecordType.RRSIG &&
            r.Data is ResourceRecordSignatureData sig &&
            sig.TypeCovered == DomainRecordType.A);
        Assert.False(result.Flags.Authentic);
    }

    [Fact]
    public async Task Cname_AdOnlyWhenEveryHopSecure()
    {
        var (dnsKey, privateKey) = CreateEcdsaDnsKey("example.com");
        var cname = new DomainResourceRecord(
            new DomainLabels("www.example.com"),
            DomainRecordType.CNAME,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(300),
            new NameData(new DomainLabels("target.example.com")));
        var cnameSig = SignRrset(privateKey, dnsKey, [cname], DomainRecordType.CNAME);
        var aRecord = new DomainResourceRecord(
            new DomainLabels("target.example.com"),
            DomainRecordType.A,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(300),
            new IPAddressData(IPAddress.Parse("192.0.2.55")));
        var aSig = SignRrset(privateKey, dnsKey, [aRecord], DomainRecordType.A);

        // Inner returns signed CNAME; chase returns signed A — both Secure in shared scope.
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(ci =>
            {
                var ctx = ci.ArgAt<DomainMessageContext>(0);
                // Simulate prior hop validation for CNAME.
                ctx.DnssecScope?.Observe(DnssecValidationStatus.Secure);
                var req = ctx.DomainMessage;
                return new ValueTask<DomainMessage>(DomainMessage.CreateResponse(
                    req, answers: [cname, cnameSig], responseCode: DomainResponseCode.NoError));
            });

        var internalClient = Substitute.For<IInternalDomainClient>();
        internalClient
            .SendAsync(Arg.Any<DomainMessageContext>(), Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
            .Returns(ci =>
            {
                var ctx = ci.ArgAt<DomainMessageContext>(0);
                ctx.DnssecScope?.Observe(DnssecValidationStatus.Secure);
                var req = ci.ArgAt<DomainMessage>(1);
                return new ValueTask<DomainMessage>(DomainMessage.CreateResponse(
                    req, answers: [aRecord, aSig], responseCode: DomainResponseCode.NoError));
            });

        var cnameDecorator = new CanonicalNameResolverDecorator(inner, internalClient);
        var cache = CreateCache();
        var crypto = new DnssecValidator(NullLogger<DnssecValidator>.Instance, Monitor(new DnsConfiguration()));
        var options = Monitor(new DnsConfiguration
        {
            TrustAnchors =
            [
                new TrustAnchorConfiguration
                {
                    Name = "example.com",
                    KeyTag = CalculateKeyTag(dnsKey),
                    Algorithm = (byte)DnssecAlgorithmType.EcdsaP256Sha256,
                    DigestType = (byte)DelegationSignerDigestType.Sha256,
                    DigestHex = ComputeDsDigestHex(dnsKey)
                }
            ]
        });
        var validator = new DnssecMessageValidator(
            crypto, NoopInternalClient(), options, NullLogger<DnssecMessageValidator>.Instance);
        var dnssec = new DnssecValidationMiddleware(
            cnameDecorator, validator, cache, options, NullLogger<DnssecValidationMiddleware>.Instance);

        var scope = new DnssecScope();
        scope.LoadTrustAnchors(options.CurrentValue.TrustAnchors!);
        scope.SetKeys(new AuthenticatedDnsKeySet { Zone = "example.com", Keys = [dnsKey] });

        var request = DomainMessage.CreateRequest("www.example.com");
        var context = new DomainMessageContext(null, null, request) { DnssecScope = scope };
        var result = await dnssec.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DnssecValidationStatus.Secure, scope.Status);
        Assert.True(result!.Flags.Authentic);
    }

    [Fact]
    public async Task Cname_InsecureHopClearsAd()
    {
        var (dnsKey, privateKey) = CreateEcdsaDnsKey("example.com");
        var cname = new DomainResourceRecord(
            new DomainLabels("www.example.com"),
            DomainRecordType.CNAME,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(300),
            new NameData(new DomainLabels("target.example.com")));
        var cnameSig = SignRrset(privateKey, dnsKey, [cname], DomainRecordType.CNAME);
        var aRecord = new DomainResourceRecord(
            new DomainLabels("target.example.com"),
            DomainRecordType.A,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(300),
            new IPAddressData(IPAddress.Parse("192.0.2.55")));

        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(ci =>
            {
                var ctx = ci.ArgAt<DomainMessageContext>(0);
                ctx.DnssecScope?.Observe(DnssecValidationStatus.Secure);
                return new ValueTask<DomainMessage>(DomainMessage.CreateResponse(
                    ctx.DomainMessage, answers: [cname, cnameSig], responseCode: DomainResponseCode.NoError));
            });

        var internalClient = Substitute.For<IInternalDomainClient>();
        internalClient
            .SendAsync(Arg.Any<DomainMessageContext>(), Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
            .Returns(ci =>
            {
                var ctx = ci.ArgAt<DomainMessageContext>(0);
                // Unsigned tip hop.
                ctx.DnssecScope?.Observe(DnssecValidationStatus.Insecure);
                var req = ci.ArgAt<DomainMessage>(1);
                return new ValueTask<DomainMessage>(DomainMessage.CreateResponse(
                    req, answers: [aRecord], responseCode: DomainResponseCode.NoError));
            });

        var cnameDecorator = new CanonicalNameResolverDecorator(inner, internalClient);
        var cache = CreateCache();
        var crypto = new DnssecValidator(NullLogger<DnssecValidator>.Instance, Monitor(new DnsConfiguration()));
        var options = Monitor(new DnsConfiguration
        {
            TrustAnchors =
            [
                new TrustAnchorConfiguration
                {
                    Name = "example.com",
                    KeyTag = CalculateKeyTag(dnsKey),
                    Algorithm = (byte)DnssecAlgorithmType.EcdsaP256Sha256,
                    DigestType = (byte)DelegationSignerDigestType.Sha256,
                    DigestHex = ComputeDsDigestHex(dnsKey)
                }
            ]
        });
        var validator = new DnssecMessageValidator(
            crypto, NoopInternalClient(), options, NullLogger<DnssecMessageValidator>.Instance);
        var dnssec = new DnssecValidationMiddleware(
            cnameDecorator, validator, cache, options, NullLogger<DnssecValidationMiddleware>.Instance);

        var scope = new DnssecScope();
        scope.LoadTrustAnchors(options.CurrentValue.TrustAnchors!);
        scope.SetKeys(new AuthenticatedDnsKeySet { Zone = "example.com", Keys = [dnsKey] });

        var request = DomainMessage.CreateRequest("www.example.com");
        var context = new DomainMessageContext(null, null, request) { DnssecScope = scope };
        var result = await dnssec.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DnssecValidationStatus.Insecure, scope.Status);
        Assert.False(result!.Flags.Authentic);
    }

    private static DnsResponseCache CreateCache()
        => new(new MemoryCache(new MemoryCacheOptions { SizeLimit = 10_000 }));

    private static (DomainResourceRecord KeyRecord, ECDsa PrivateKey) CreateEcdsaDnsKey(string zone)
    {
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pub = ecdsa.ExportParameters(false);
        var pubKey = new byte[64];
        pub.Q.X!.CopyTo(pubKey, 0);
        pub.Q.Y!.CopyTo(pubKey, 32);

        var data = new DomainNameSystemKeyData(
            257,
            3,
            DnssecAlgorithmType.EcdsaP256Sha256,
            pubKey.ToImmutableArray());

        return (new DomainResourceRecord(
            new DomainLabels(zone),
            DomainRecordType.DNSKEY,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(3600),
            data), ecdsa);
    }

    private static DomainResourceRecord SignRrset(
        ECDsa privateKey,
        DomainResourceRecord dnsKeyRecord,
        IReadOnlyList<DomainResourceRecord> rrset,
        DomainRecordType typeCovered)
    {
        var crypto = new DnssecValidator(NullLogger<DnssecValidator>.Instance, Monitor(new DnsConfiguration()));
        var keyTag = crypto.CalculateKeyTag((DomainNameSystemKeyData)dnsKeyRecord.Data, dnsKeyRecord);
        var now = DateTimeOffset.UtcNow;
        var rrsigData = new ResourceRecordSignatureData(
            typeCovered,
            DnssecAlgorithmType.EcdsaP256Sha256,
            (byte)rrset[0].Name.Labels.Length,
            300,
            (uint)now.AddDays(1).ToUnixTimeSeconds(),
            (uint)now.AddDays(-1).ToUnixTimeSeconds(),
            keyTag,
            dnsKeyRecord.Name,
            ImmutableArray<byte>.Empty);

        var prefix = DnssecRrsetVerifier.EncodeRrsigWithoutSignature(rrsigData);
        var canonical = DnssecRrsetVerifier.BuildCanonicalRrset(rrset, 300);
        var payload = new byte[prefix.Length + canonical.Length];
        prefix.CopyTo(payload, 0);
        canonical.CopyTo(payload, prefix.Length);

        var signature = privateKey.SignData(
            payload,
            HashAlgorithmName.SHA256,
            DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        rrsigData = rrsigData with { Signature = signature.ToImmutableArray() };
        return new DomainResourceRecord(
            rrset[0].Name,
            DomainRecordType.RRSIG,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(300),
            rrsigData);
    }

    private static ushort CalculateKeyTag(DomainResourceRecord dnsKeyRecord)
    {
        var crypto = new DnssecValidator(NullLogger<DnssecValidator>.Instance, Monitor(new DnsConfiguration()));
        return crypto.CalculateKeyTag((DomainNameSystemKeyData)dnsKeyRecord.Data, dnsKeyRecord);
    }

    private static string ComputeDsDigestHex(DomainResourceRecord dnsKeyRecord)
    {
        var size = dnsKeyRecord.EstimatedSize;
        var buffer = new byte[size * 2];
        var span = buffer.AsSpan();
        DomainResourceRecordCanonicalizationExtensions.EncodeCanonicalName(ref span, dnsKeyRecord.Name);
        var offset = buffer.Length - span.Length;
        using (var dict = Dhcpr.Core.Linq.DictionaryPool<string, int>.Default.Get())
        {
            var parsingSpan = new Protocol.Parser.DnsParsingSpan(dict, buffer.AsSpan(offset));
            dnsKeyRecord.Data.WriteTo(ref parsingSpan);
            var rdataLen = parsingSpan.Offset - 2;
            buffer.AsSpan(offset + 2, rdataLen).CopyTo(buffer.AsSpan(offset));
            offset += rdataLen;
        }

        return Convert.ToHexString(SHA256.HashData(buffer.AsSpan(0, offset)));
    }

    private static IInternalDomainClient NoopInternalClient()
    {
        var client = Substitute.For<IInternalDomainClient>();
        client.SendAsync(Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
            .Returns(ci => new ValueTask<DomainMessage>(
                DomainMessage.CreateResponse(
                    ci.Arg<DomainMessage>(),
                    DomainResourceRecords.Empty,
                    DomainResponseCode.ServerFailure)));
        client.SendAsync(Arg.Any<DomainMessageContext>(), Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
            .Returns(ci => new ValueTask<DomainMessage>(
                DomainMessage.CreateResponse(
                    ci.ArgAt<DomainMessage>(1),
                    DomainResourceRecords.Empty,
                    DomainResponseCode.ServerFailure)));
        client.SendAsync(
                Arg.Any<DomainMessageContext>(),
                Arg.Any<DomainMessage>(),
                Arg.Any<ImmutableArray<IPEndPoint>>(),
                Arg.Any<CancellationToken>())
            .Returns(ci => new ValueTask<DomainMessage>(
                DomainMessage.CreateResponse(
                    ci.ArgAt<DomainMessage>(1),
                    DomainResourceRecords.Empty,
                    DomainResponseCode.ServerFailure)));
        return client;
    }

    private static IOptionsMonitor<T> Monitor<T>(T value)
    {
        var monitor = Substitute.For<IOptionsMonitor<T>>();
        monitor.CurrentValue.Returns(value);
        monitor.Get(Arg.Any<string?>()).Returns(value);
        return monitor;
    }
}
