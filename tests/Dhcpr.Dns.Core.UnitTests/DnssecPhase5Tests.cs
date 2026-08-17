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

/// <summary>
/// Phase 5: config knobs, quieter client failure logging, multi-hop signed-zone integration.
/// </summary>
public class DnssecPhase5Tests
{
    [Theory]
    [InlineData(8, true)]
    [InlineData(13, true)]
    [InlineData(5, false)]
    public void DefaultPolicy_AllowsBuiltInAlgorithmsOnly(byte algorithm, bool expected)
    {
        var policy = new DnssecConfiguration();
        Assert.Equal(expected, policy.IsAlgorithmAllowed(algorithm));
    }

    [Fact]
    public void DeniedAlgorithms_OverrideAllowList()
    {
        var policy = new DnssecConfiguration
        {
            AllowedAlgorithms = [8, 13],
            DeniedAlgorithms = [13]
        };
        Assert.True(policy.IsAlgorithmAllowed(8));
        Assert.False(policy.IsAlgorithmAllowed(13));
    }

    [Fact]
    public void ExplicitAllowList_RestrictsAlgorithms()
    {
        var policy = new DnssecConfiguration { AllowedAlgorithms = [8] };
        Assert.True(policy.IsAlgorithmAllowed(8));
        Assert.False(policy.IsAlgorithmAllowed(13));
    }

    [Fact]
    public void DeniedAlgorithm_CannotVerifySignature()
    {
        var (dnsKey, privateKey) = CreateEcdsaDnsKey("example.com");
        var aRecord = A("www.example.com", "192.0.2.10");
        var rrsig = SignRrset(privateKey, dnsKey, [aRecord], DomainRecordType.A);

        var options = Options(new DnsConfiguration
        {
            Dnssec = new DnssecConfiguration { DeniedAlgorithms = [(byte)DnssecAlgorithmType.EcdsaP256Sha256] }
        });
        var crypto = new DnssecValidator(NullLogger<DnssecValidator>.Instance, options);

        Assert.False(DnssecRrsetVerifier.TryVerifyRrset(
            crypto, [aRecord], [rrsig], [dnsKey], DateTimeOffset.UtcNow));
    }

    [Fact]
    public async Task Disabled_SkipsValidation_NoAdNoServFail()
    {
        var (dnsKey, privateKey) = CreateEcdsaDnsKey("example.com");
        var aRecord = A("www.example.com", "192.0.2.10");
        var rrsig = SignRrset(privateKey, dnsKey, [aRecord], DomainRecordType.A);
        var tampered = aRecord with { Data = new IPAddressData(IPAddress.Parse("203.0.113.1")) };

        var request = DomainMessage.CreateRequest("www.example.com");
        var response = DomainMessage.CreateResponse(
            request, answers: [tampered, rrsig], responseCode: DomainResponseCode.NoError);

        var options = Options(new DnsConfiguration
        {
            Dnssec = new DnssecConfiguration { Enabled = false },
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

        var middleware = CreateMiddleware(response, options);
        var scope = new DnssecScope();
        var result = await middleware.ProcessAsync(
            new DomainMessageContext(null, null, request) { DnssecScope = scope },
            CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NoError, result!.Flags.ResponseCode);
        Assert.False(result.Flags.Authentic);
        Assert.Equal(DnssecValidationStatus.Unchecked, scope.Status);
    }

    [Fact]
    public async Task MultiHop_ParentChild_SetsAdWhenSecure()
    {
        // Parent zone example.com (TA) → child.example.com (DS at parent) → A at child.
        var (parentKey, parentPrivate) = CreateEcdsaDnsKey("example.com");
        var (childKey, childPrivate) = CreateEcdsaDnsKey("child.example.com");

        var ds = CreateDsRecord("child.example.com", childKey);
        var dsSig = SignRrset(parentPrivate, parentKey, [ds], DomainRecordType.DS);

        var aRecord = A("www.child.example.com", "192.0.2.77");
        var aSig = SignRrset(childPrivate, childKey, [aRecord], DomainRecordType.A);

        var childDnsKeySig = SignRrset(childPrivate, childKey, [childKey], DomainRecordType.DNSKEY);
        var parentDnsKeySig = SignRrset(parentPrivate, parentKey, [parentKey], DomainRecordType.DNSKEY);

        var internalClient = new ScriptedInternalClient(request =>
        {
            var q = request.Questions[0];
            var name = q.Name.ToString();
            if (q.Type is DomainRecordType.DNSKEY && name.Equals("example.com", StringComparison.OrdinalIgnoreCase))
                return DomainMessage.CreateResponse(request, answers: [parentKey, parentDnsKeySig], responseCode: DomainResponseCode.NoError);
            if (q.Type is DomainRecordType.DNSKEY && name.Equals("child.example.com", StringComparison.OrdinalIgnoreCase))
                return DomainMessage.CreateResponse(request, answers: [childKey, childDnsKeySig], responseCode: DomainResponseCode.NoError);
            if (q.Type is DomainRecordType.DS && name.Equals("child.example.com", StringComparison.OrdinalIgnoreCase))
                return DomainMessage.CreateResponse(request, answers: [ds, dsSig], responseCode: DomainResponseCode.NoError);
            return DomainMessage.CreateResponse(request, DomainResourceRecords.Empty, DomainResponseCode.ServerFailure);
        });

        var request = DomainMessage.CreateRequest("www.child.example.com");
        var response = DomainMessage.CreateResponse(
            request, answers: [aRecord, aSig], responseCode: DomainResponseCode.NoError);

        var options = Options(new DnsConfiguration
        {
            TrustAnchors =
            [
                new TrustAnchorConfiguration
                {
                    Name = "example.com",
                    KeyTag = CalculateKeyTag(parentKey),
                    Algorithm = (byte)DnssecAlgorithmType.EcdsaP256Sha256,
                    DigestType = (byte)DelegationSignerDigestType.Sha256,
                    DigestHex = ComputeDsDigestHex(parentKey)
                }
            ]
        });

        var middleware = CreateMiddleware(response, options, internalClient);
        var scope = new DnssecScope();
        var result = await middleware.ProcessAsync(
            new DomainMessageContext(null, null, request) { DnssecScope = scope },
            CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DnssecValidationStatus.Secure, scope.Status);
        Assert.True(result!.Flags.Authentic);
        Assert.Equal(DomainResponseCode.NoError, result.Flags.ResponseCode);
        Assert.True(scope.TryGetKeys("child.example.com", out _));
        Assert.True(scope.TryGetDelegation("child.example.com", out _));
    }

    [Fact]
    public async Task MultiHop_TamperedAnswer_ServFailsWhenCdClear()
    {
        var (parentKey, parentPrivate) = CreateEcdsaDnsKey("example.com");
        var (childKey, childPrivate) = CreateEcdsaDnsKey("child.example.com");
        var ds = CreateDsRecord("child.example.com", childKey);
        var dsSig = SignRrset(parentPrivate, parentKey, [ds], DomainRecordType.DS);
        var aRecord = A("www.child.example.com", "192.0.2.77");
        var aSig = SignRrset(childPrivate, childKey, [aRecord], DomainRecordType.A);
        var tampered = aRecord with { Data = new IPAddressData(IPAddress.Parse("203.0.113.9")) };
        var childDnsKeySig = SignRrset(childPrivate, childKey, [childKey], DomainRecordType.DNSKEY);
        var parentDnsKeySig = SignRrset(parentPrivate, parentKey, [parentKey], DomainRecordType.DNSKEY);

        var internalClient = new ScriptedInternalClient(request =>
        {
            var q = request.Questions[0];
            var name = q.Name.ToString();
            if (q.Type is DomainRecordType.DNSKEY && name.Equals("example.com", StringComparison.OrdinalIgnoreCase))
                return DomainMessage.CreateResponse(request, answers: [parentKey, parentDnsKeySig], responseCode: DomainResponseCode.NoError);
            if (q.Type is DomainRecordType.DNSKEY && name.Equals("child.example.com", StringComparison.OrdinalIgnoreCase))
                return DomainMessage.CreateResponse(request, answers: [childKey, childDnsKeySig], responseCode: DomainResponseCode.NoError);
            if (q.Type is DomainRecordType.DS && name.Equals("child.example.com", StringComparison.OrdinalIgnoreCase))
                return DomainMessage.CreateResponse(request, answers: [ds, dsSig], responseCode: DomainResponseCode.NoError);
            return DomainMessage.CreateResponse(request, DomainResourceRecords.Empty, DomainResponseCode.ServerFailure);
        });

        var request = DomainMessage.CreateRequest("www.child.example.com");
        var response = DomainMessage.CreateResponse(
            request, answers: [tampered, aSig], responseCode: DomainResponseCode.NoError);

        var options = Options(new DnsConfiguration
        {
            TrustAnchors =
            [
                new TrustAnchorConfiguration
                {
                    Name = "example.com",
                    KeyTag = CalculateKeyTag(parentKey),
                    Algorithm = (byte)DnssecAlgorithmType.EcdsaP256Sha256,
                    DigestType = (byte)DelegationSignerDigestType.Sha256,
                    DigestHex = ComputeDsDigestHex(parentKey)
                }
            ]
        });

        var middleware = CreateMiddleware(response, options, internalClient);
        var scope = new DnssecScope();
        var result = await middleware.ProcessAsync(
            new DomainMessageContext(null, null, request) { DnssecScope = scope },
            CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DnssecValidationStatus.Bogus, scope.Status);
        Assert.Equal(DomainResponseCode.ServerFailure, result!.Flags.ResponseCode);
        Assert.False(result.Flags.Authentic);
    }

    [Fact]
    public async Task MultiHop_TamperedAnswer_PassesThroughWhenCdSet()
    {
        var (parentKey, parentPrivate) = CreateEcdsaDnsKey("example.com");
        var (childKey, childPrivate) = CreateEcdsaDnsKey("child.example.com");
        var ds = CreateDsRecord("child.example.com", childKey);
        var dsSig = SignRrset(parentPrivate, parentKey, [ds], DomainRecordType.DS);
        var aRecord = A("www.child.example.com", "192.0.2.77");
        var aSig = SignRrset(childPrivate, childKey, [aRecord], DomainRecordType.A);
        var tampered = aRecord with { Data = new IPAddressData(IPAddress.Parse("203.0.113.9")) };
        var childDnsKeySig = SignRrset(childPrivate, childKey, [childKey], DomainRecordType.DNSKEY);
        var parentDnsKeySig = SignRrset(parentPrivate, parentKey, [parentKey], DomainRecordType.DNSKEY);

        var internalClient = new ScriptedInternalClient(request =>
        {
            var q = request.Questions[0];
            var name = q.Name.ToString();
            if (q.Type is DomainRecordType.DNSKEY && name.Equals("example.com", StringComparison.OrdinalIgnoreCase))
                return DomainMessage.CreateResponse(request, answers: [parentKey, parentDnsKeySig], responseCode: DomainResponseCode.NoError);
            if (q.Type is DomainRecordType.DNSKEY && name.Equals("child.example.com", StringComparison.OrdinalIgnoreCase))
                return DomainMessage.CreateResponse(request, answers: [childKey, childDnsKeySig], responseCode: DomainResponseCode.NoError);
            if (q.Type is DomainRecordType.DS && name.Equals("child.example.com", StringComparison.OrdinalIgnoreCase))
                return DomainMessage.CreateResponse(request, answers: [ds, dsSig], responseCode: DomainResponseCode.NoError);
            return DomainMessage.CreateResponse(request, DomainResourceRecords.Empty, DomainResponseCode.ServerFailure);
        });

        var request = DomainMessage.CreateRequest("www.child.example.com") with
        {
            Flags = DomainMessage.CreateRequest("www.child.example.com").Flags with { CheckingDisabled = true }
        };
        var response = DomainMessage.CreateResponse(
            request, answers: [tampered, aSig], responseCode: DomainResponseCode.NoError);

        var options = Options(new DnsConfiguration
        {
            TrustAnchors =
            [
                new TrustAnchorConfiguration
                {
                    Name = "example.com",
                    KeyTag = CalculateKeyTag(parentKey),
                    Algorithm = (byte)DnssecAlgorithmType.EcdsaP256Sha256,
                    DigestType = (byte)DelegationSignerDigestType.Sha256,
                    DigestHex = ComputeDsDigestHex(parentKey)
                }
            ]
        });

        var middleware = CreateMiddleware(response, options, internalClient);
        var scope = new DnssecScope();
        var result = await middleware.ProcessAsync(
            new DomainMessageContext(null, null, request) { DnssecScope = scope },
            CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DnssecValidationStatus.Bogus, scope.Status);
        Assert.Equal(DomainResponseCode.NoError, result!.Flags.ResponseCode);
        Assert.False(result.Flags.Authentic);
        Assert.Contains(result.Records.Answers, r => r.Type == DomainRecordType.A);
    }

    [Fact]
    public async Task KeyFetch_DoesNotReuseHopUpstreamEndpoints()
    {
        var (parentKey, parentPrivate) = CreateEcdsaDnsKey("example.com");
        var aRecord = A("www.example.com", "192.0.2.10");
        var aSig = SignRrset(parentPrivate, parentKey, [aRecord], DomainRecordType.A);
        var parentDnsKeySig = SignRrset(parentPrivate, parentKey, [parentKey], DomainRecordType.DNSKEY);

        var leafNs = new IPEndPoint(IPAddress.Parse("203.0.113.50"), 53);
        var sawDirectedKeyFetch = false;
        var sawUndirectedKeyFetch = false;

        var internalClient = new ScriptedInternalClient((parentContext, request) =>
        {
            var q = request.Questions[0];
            if (q.Type is DomainRecordType.DNSKEY)
            {
                if (parentContext.UpstreamEndpoints is { Length: > 0 })
                    sawDirectedKeyFetch = true;
                else
                    sawUndirectedKeyFetch = true;

                return DomainMessage.CreateResponse(
                    request, answers: [parentKey, parentDnsKeySig], responseCode: DomainResponseCode.NoError);
            }

            return DomainMessage.CreateResponse(
                request, DomainResourceRecords.Empty, DomainResponseCode.ServerFailure);
        });

        var request = DomainMessage.CreateRequest("www.example.com");
        var response = DomainMessage.CreateResponse(
            request, answers: [aRecord, aSig], responseCode: DomainResponseCode.NoError);

        var options = Options(new DnsConfiguration
        {
            TrustAnchors =
            [
                new TrustAnchorConfiguration
                {
                    Name = "example.com",
                    KeyTag = CalculateKeyTag(parentKey),
                    Algorithm = (byte)DnssecAlgorithmType.EcdsaP256Sha256,
                    DigestType = (byte)DelegationSignerDigestType.Sha256,
                    DigestHex = ComputeDsDigestHex(parentKey)
                }
            ]
        });

        var middleware = CreateMiddleware(response, options, internalClient);
        var scope = new DnssecScope();
        var context = new DomainMessageContext(null, null, request)
        {
            DnssecScope = scope,
            // Simulate validating a hop answered by a leaf nameserver.
            UpstreamEndpoints = [leafNs]
        };

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.False(sawDirectedKeyFetch);
        Assert.True(sawUndirectedKeyFetch);
        Assert.Equal(DnssecValidationStatus.Secure, scope.Status);
    }

    [Fact]
    public void IgnoreStatus_BlocksObserveButKeepsKeys()
    {
        var scope = new DnssecScope();
        scope.Observe(DnssecValidationStatus.Secure);
        scope.PushIgnoreStatus();
        scope.Observe(DnssecValidationStatus.Bogus);
        scope.Observe(DnssecValidationStatus.Insecure);
        scope.PopIgnoreStatus();
        Assert.Equal(DnssecValidationStatus.Secure, scope.Status);

        scope.Observe(DnssecValidationStatus.Insecure);
        Assert.Equal(DnssecValidationStatus.Insecure, scope.Status);
    }

    [Fact]
    public async Task SuppressKeyFetch_DoesNotPoisonScopeWithBogus()
    {
        var (parentKey, parentPrivate) = CreateEcdsaDnsKey("example.com");
        var aRecord = A("www.example.com", "192.0.2.10");
        var aSig = SignRrset(parentPrivate, parentKey, [aRecord], DomainRecordType.A);
        var parentDnsKeySig = SignRrset(parentPrivate, parentKey, [parentKey], DomainRecordType.DNSKEY);

        // While SuppressKeyFetch is set, nested validation of a signed referral would
        // previously Observe(Bogus) because EnsureZoneKeysAvailable returns false.
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(ci =>
            {
                var ctx = ci.ArgAt<DomainMessageContext>(0);
                Assert.True(ctx.DnssecScope!.SuppressKeyFetch);
                // Signed NS referral (DS RRSIG present) — must not Bogus the scope.
                var ns = new DomainResourceRecord(
                    new DomainLabels("example.com"),
                    DomainRecordType.NS,
                    DomainRecordClass.IN,
                    TimeSpan.FromSeconds(300),
                    new NameData(new DomainLabels("ns.example.com")));
                var ds = CreateDsRecord("child.example.com", parentKey);
                var dsSig = SignRrset(parentPrivate, parentKey, [ds], DomainRecordType.DS);
                return new ValueTask<DomainMessage?>(DomainMessage.CreateResponse(
                    ctx.DomainMessage,
                    answers: [],
                    authorities: [ns, ds, dsSig],
                    responseCode: DomainResponseCode.NoError));
            });

        var cache = new DnsResponseCache(new MemoryCache(new MemoryCacheOptions { SizeLimit = 1000 }));
        var options = Options(new DnsConfiguration
        {
            TrustAnchors =
            [
                new TrustAnchorConfiguration
                {
                    Name = "example.com",
                    KeyTag = CalculateKeyTag(parentKey),
                    Algorithm = (byte)DnssecAlgorithmType.EcdsaP256Sha256,
                    DigestType = (byte)DelegationSignerDigestType.Sha256,
                    DigestHex = ComputeDsDigestHex(parentKey)
                }
            ]
        });
        var crypto = new DnssecValidator(NullLogger<DnssecValidator>.Instance, options);
        var validator = new DnssecMessageValidator(
            crypto, new ScriptedInternalClient(_ =>
                DomainMessage.CreateResponse(
                    DomainMessage.CreateRequest("."), DomainResourceRecords.Empty, DomainResponseCode.ServerFailure)),
            options, NullLogger<DnssecMessageValidator>.Instance);
        var dnssec = new DnssecValidationMiddleware(
            inner, validator, cache, options, NullLogger<DnssecValidationMiddleware>.Instance);

        var scope = new DnssecScope();
        scope.LoadTrustAnchors(options.CurrentValue.TrustAnchors!);
        scope.SetKeys(new AuthenticatedDnsKeySet { Zone = "example.com", Keys = [parentKey] });
        scope.SuppressKeyFetch = true;

        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.NS);
        var result = await dnssec.ProcessAsync(
            new DomainMessageContext(null, null, request)
            {
                DnssecScope = scope,
                IsInternal = true,
                UpstreamEndpoints = [new IPEndPoint(IPAddress.Parse("192.0.2.53"), 53)]
            },
            CancellationToken.None);

        Assert.NotNull(result);
        Assert.NotEqual(DnssecValidationStatus.Bogus, scope.Status);
        _ = aRecord;
        _ = aSig;
        _ = parentDnsKeySig;
    }

    [Fact]
    public async Task UnsignedDirectedGlue_DoesNotMarkScopeInsecure()
    {
        var request = DomainMessage.CreateRequest("ns.example.com", DomainRecordType.A);
        var response = DomainMessage.CreateResponse(
            request,
            answers: [A("ns.example.com", "192.0.2.53")],
            responseCode: DomainResponseCode.NoError);

        var options = Options(new DnsConfiguration());
        var middleware = CreateMiddleware(response, options);
        var scope = new DnssecScope();
        scope.Observe(DnssecValidationStatus.Secure);

        await middleware.ProcessAsync(
            new DomainMessageContext(null, null, request)
            {
                DnssecScope = scope,
                IsInternal = true,
                UpstreamEndpoints = [new IPEndPoint(IPAddress.Parse("192.0.2.1"), 53)]
            },
            CancellationToken.None);

        Assert.Equal(DnssecValidationStatus.Secure, scope.Status);
    }

    private static DnssecValidationMiddleware CreateMiddleware(
        DomainMessage response,
        IOptionsMonitor<DnsConfiguration> options,
        IInternalDomainClient? internalClient = null)
    {
        var crypto = new DnssecValidator(NullLogger<DnssecValidator>.Instance, options);
        var messageValidator = new DnssecMessageValidator(
            crypto,
            internalClient ?? new ScriptedInternalClient(_ =>
                DomainMessage.CreateResponse(
                    DomainMessage.CreateRequest("."), DomainResourceRecords.Empty, DomainResponseCode.ServerFailure)),
            options,
            NullLogger<DnssecMessageValidator>.Instance);

        return new DnssecValidationMiddleware(
            new FixedInner(response),
            messageValidator,
            new DnsResponseCache(new MemoryCache(new MemoryCacheOptions { SizeLimit = 1000 })),
            options,
            NullLogger<DnssecValidationMiddleware>.Instance);
    }

    private static IOptionsMonitor<DnsConfiguration> Options(DnsConfiguration config)
    {
        var monitor = Substitute.For<IOptionsMonitor<DnsConfiguration>>();
        monitor.CurrentValue.Returns(config);
        monitor.Get(Arg.Any<string?>()).Returns(config);
        return monitor;
    }

    private static DomainResourceRecord A(string name, string ip) => new(
        new DomainLabels(name),
        DomainRecordType.A,
        DomainRecordClass.IN,
        TimeSpan.FromSeconds(300),
        new IPAddressData(IPAddress.Parse(ip)));

    private static DomainResourceRecord CreateDsRecord(string childZone, DomainResourceRecord childDnsKey)
        => new(
            new DomainLabels(childZone),
            DomainRecordType.DS,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(300),
            new DelegationSignerData(
                CalculateKeyTag(childDnsKey),
                DnssecAlgorithmType.EcdsaP256Sha256,
                DelegationSignerDigestType.Sha256,
                Convert.FromHexString(ComputeDsDigestHex(childDnsKey)).ToImmutableArray()));

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
        var crypto = new DnssecValidator(NullLogger<DnssecValidator>.Instance);
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
        var crypto = new DnssecValidator(NullLogger<DnssecValidator>.Instance);
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

    private sealed class FixedInner : IDomainMessageMiddleware
    {
        private readonly DomainMessage _response;
        public FixedInner(DomainMessage response) => _response = response;
        public int Priority => 1;
        public ValueTask<DomainMessage?> ProcessAsync(DomainMessageContext context, CancellationToken cancellationToken)
            => ValueTask.FromResult<DomainMessage?>(_response);
    }

    private sealed class ScriptedInternalClient : IInternalDomainClient
    {
        private readonly Func<DomainMessageContext, DomainMessage, DomainMessage> _handler;

        public ScriptedInternalClient(Func<DomainMessage, DomainMessage> handler)
            : this((_, request) => handler(request))
        {
        }

        public ScriptedInternalClient(Func<DomainMessageContext, DomainMessage, DomainMessage> handler)
        {
            _handler = handler;
        }

        public ValueTask<DomainMessage> SendAsync(DomainMessage message, CancellationToken cancellationToken)
            => ValueTask.FromResult(_handler(
                new DomainMessageContext(null, null, message) { IsInternal = true },
                message));

        public ValueTask<DomainMessage> SendAsync(
            DomainMessageContext parentContext,
            DomainMessage message,
            CancellationToken cancellationToken)
            => ValueTask.FromResult(_handler(
                parentContext with { UpstreamEndpoints = null },
                message));

        public ValueTask<DomainMessage> SendAsync(
            DomainMessageContext parentContext,
            DomainMessage message,
            ImmutableArray<IPEndPoint> upstreamEndpoints,
            CancellationToken cancellationToken)
            => ValueTask.FromResult(_handler(
                parentContext with { UpstreamEndpoints = upstreamEndpoints },
                message));
    }

}
