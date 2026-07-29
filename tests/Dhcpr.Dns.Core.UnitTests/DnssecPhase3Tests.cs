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

namespace Dhcpr.Dns.Core.UnitTests;

public class DnssecPhase3Tests
{
    [Fact]
    public void RrsetVerifier_AcceptsValidEcdsaSignature()
    {
        var (dnsKeyRecord, privateKey) = CreateEcdsaDnsKey("example.com");
        var aRecord = new DomainResourceRecord(
            new DomainLabels("www.example.com"),
            DomainRecordType.A,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(300),
            new IPAddressData(IPAddress.Parse("192.0.2.10")));

        var rrsig = SignRrset(privateKey, dnsKeyRecord, [aRecord], DomainRecordType.A);
        var crypto = new DnssecValidator(NullLogger<DnssecValidator>.Instance);

        Assert.True(DnssecRrsetVerifier.TryVerifyRrset(
            crypto,
            [aRecord],
            [rrsig],
            [dnsKeyRecord],
            DateTimeOffset.UtcNow));
    }

    [Fact]
    public void RrsetVerifier_RejectsTamperedRrset()
    {
        var (dnsKeyRecord, privateKey) = CreateEcdsaDnsKey("example.com");
        var aRecord = new DomainResourceRecord(
            new DomainLabels("www.example.com"),
            DomainRecordType.A,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(300),
            new IPAddressData(IPAddress.Parse("192.0.2.10")));

        var rrsig = SignRrset(privateKey, dnsKeyRecord, [aRecord], DomainRecordType.A);
        var tampered = aRecord with
        {
            Data = new IPAddressData(IPAddress.Parse("192.0.2.99"))
        };
        var crypto = new DnssecValidator(NullLogger<DnssecValidator>.Instance);

        Assert.False(DnssecRrsetVerifier.TryVerifyRrset(
            crypto,
            [tampered],
            [rrsig],
            [dnsKeyRecord],
            DateTimeOffset.UtcNow));
    }

    [Fact]
    public void Scope_LoadsTrustAnchorsAndCombinesStatus()
    {
        var scope = new DnssecScope();
        scope.LoadTrustAnchors([new TrustAnchorConfiguration()]);
        Assert.True(scope.TryGetDelegation(".", out var ta));
        Assert.True(ta.IsTrustAnchor);
        Assert.Equal(20326, ta.Digests[0].KeyTag);

        Assert.Equal(DnssecValidationStatus.Secure,
            DnssecScope.Combine(DnssecValidationStatus.Unchecked, DnssecValidationStatus.Secure));
        Assert.Equal(DnssecValidationStatus.Bogus,
            DnssecScope.Combine(DnssecValidationStatus.Secure, DnssecValidationStatus.Bogus));
        Assert.Equal(DnssecValidationStatus.Insecure,
            DnssecScope.Combine(DnssecValidationStatus.Secure, DnssecValidationStatus.Insecure));
    }

    [Fact]
    public async Task Middleware_SetsAdWhenScopeSecure()
    {
        var (dnsKeyRecord, privateKey) = CreateEcdsaDnsKey("example.com");
        var aRecord = new DomainResourceRecord(
            new DomainLabels("www.example.com"),
            DomainRecordType.A,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(300),
            new IPAddressData(IPAddress.Parse("192.0.2.10")));
        var rrsig = SignRrset(privateKey, dnsKeyRecord, [aRecord], DomainRecordType.A);

        var request = DomainMessage.CreateRequest("www.example.com");
        var response = DomainMessage.CreateResponse(
            request,
            answers: [aRecord, rrsig],
            responseCode: DomainResponseCode.NoError);

        var scope = new DnssecScope();
        scope.LoadTrustAnchors([new TrustAnchorConfiguration
        {
            Name = "example.com",
            KeyTag = CalculateKeyTag(dnsKeyRecord),
            Algorithm = (byte)DnssecAlgorithmType.EcdsaP256Sha256,
            DigestType = (byte)DelegationSignerDigestType.Sha256,
            DigestHex = ComputeDsDigestHex(dnsKeyRecord, DelegationSignerDigestType.Sha256)
        }]);
        scope.SetKeys(new AuthenticatedDnsKeySet
        {
            Zone = "example.com",
            Keys = [dnsKeyRecord]
        });

        var middleware = CreateMiddleware(response);
        var context = new DomainMessageContext(null, null, request) { DnssecScope = scope };

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DnssecValidationStatus.Secure, scope.Status);
        Assert.True(result!.Flags.Authentic);
    }

    [Fact]
    public async Task Middleware_ServFailsWhenBogusAndCdClear()
    {
        var (dnsKeyRecord, privateKey) = CreateEcdsaDnsKey("example.com");
        var aRecord = new DomainResourceRecord(
            new DomainLabels("www.example.com"),
            DomainRecordType.A,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(300),
            new IPAddressData(IPAddress.Parse("192.0.2.10")));
        var rrsig = SignRrset(privateKey, dnsKeyRecord, [aRecord], DomainRecordType.A);
        var tampered = aRecord with
        {
            Data = new IPAddressData(IPAddress.Parse("203.0.113.1"))
        };

        var request = DomainMessage.CreateRequest("www.example.com");
        var response = DomainMessage.CreateResponse(
            request,
            answers: [tampered, rrsig],
            responseCode: DomainResponseCode.NoError);

        var scope = new DnssecScope();
        scope.SetKeys(new AuthenticatedDnsKeySet
        {
            Zone = "example.com",
            Keys = [dnsKeyRecord]
        });
        // Fake DS so EnsureZoneKeys doesn't try to fetch.
        scope.SetDelegation(new AuthenticatedDelegation
        {
            Zone = "example.com",
            Digests =
            [
                new DelegationSignerData(
                    CalculateKeyTag(dnsKeyRecord),
                    DnssecAlgorithmType.EcdsaP256Sha256,
                    DelegationSignerDigestType.Sha256,
                    Convert.FromHexString(
                        ComputeDsDigestHex(dnsKeyRecord, DelegationSignerDigestType.Sha256)).ToImmutableArray())
            ],
            IsTrustAnchor = true
        });

        var middleware = CreateMiddleware(response);
        var context = new DomainMessageContext(null, null, request) { DnssecScope = scope };

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DnssecValidationStatus.Bogus, scope.Status);
        Assert.Equal(DomainResponseCode.ServerFailure, result!.Flags.ResponseCode);
        Assert.False(result.Flags.Authentic);
    }

    [Fact]
    public async Task Middleware_UnsignedResponseIsInsecureWithoutAd()
    {
        var request = DomainMessage.CreateRequest("www.example.com");
        var response = DomainMessage.CreateResponse(
            request,
            answers:
            [
                new DomainResourceRecord(
                    request.Questions[0].Name,
                    DomainRecordType.A,
                    DomainRecordClass.IN,
                    TimeSpan.FromSeconds(60),
                    new IPAddressData(IPAddress.Parse("192.0.2.1")))
            ],
            responseCode: DomainResponseCode.NoError);

        var scope = new DnssecScope();
        var middleware = CreateMiddleware(response);
        var context = new DomainMessageContext(null, null, request) { DnssecScope = scope };

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DnssecValidationStatus.Insecure, scope.Status);
        Assert.False(result!.Flags.Authentic);
        Assert.Equal(DomainResponseCode.NoError, result.Flags.ResponseCode);
    }

    private static DnssecValidationMiddleware CreateMiddleware(DomainMessage response)
    {
        var crypto = new DnssecValidator(NullLogger<DnssecValidator>.Instance);
        var options = new StaticOptionsMonitor<DnsConfiguration>(new DnsConfiguration
        {
            TrustAnchors = [new TrustAnchorConfiguration()]
        });
        var messageValidator = new DnssecMessageValidator(
            crypto,
            new NoopInternalClient(),
            options,
            NullLogger<DnssecMessageValidator>.Instance);

        return new DnssecValidationMiddleware(
            new FixedInner(response),
            messageValidator,
            new DnsResponseCache(new MemoryCache(new MemoryCacheOptions { SizeLimit = 1000 })),
            NullLogger<DnssecValidationMiddleware>.Instance);
    }

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

        var record = new DomainResourceRecord(
            zone is "." ? DomainLabels.Empty : new DomainLabels(zone),
            DomainRecordType.DNSKEY,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(3600),
            data);

        return (record, ecdsa);
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

    private static string ComputeDsDigestHex(DomainResourceRecord dnsKeyRecord, DelegationSignerDigestType digestType)
    {
        var crypto = new DnssecValidator(NullLogger<DnssecValidator>.Instance);
        // Brute: try VerifyDelegationSigner against a constructed DS by computing via validator path.
        // Use the same encoding as DnssecValidator.VerifyDelegationSigner.
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

        var payload = buffer.AsSpan(0, offset);
        var digest = digestType switch
        {
            DelegationSignerDigestType.Sha1 => SHA1.HashData(payload),
            DelegationSignerDigestType.Sha256 => SHA256.HashData(payload),
            DelegationSignerDigestType.Sha384 => SHA384.HashData(payload),
            _ => throw new ArgumentOutOfRangeException(nameof(digestType))
        };

        // silence unused
        _ = crypto;
        return Convert.ToHexString(digest);
    }

    private sealed class FixedInner : IDomainMessageMiddleware
    {
        private readonly DomainMessage _response;
        public FixedInner(DomainMessage response) => _response = response;
        public int Priority => 1;
        public ValueTask<DomainMessage?> ProcessAsync(DomainMessageContext context, CancellationToken cancellationToken)
            => ValueTask.FromResult<DomainMessage?>(_response);
    }

    private sealed class NoopInternalClient : IInternalDomainClient
    {
        public ValueTask<DomainMessage> SendAsync(DomainMessage message, CancellationToken cancellationToken)
            => ValueTask.FromResult(DomainMessage.CreateResponse(message, DomainResourceRecords.Empty, DomainResponseCode.ServerFailure));

        public ValueTask<DomainMessage> SendAsync(
            DomainMessageContext parentContext,
            DomainMessage message,
            CancellationToken cancellationToken)
            => SendAsync(message, cancellationToken);

        public ValueTask<DomainMessage> SendAsync(
            DomainMessageContext parentContext,
            DomainMessage message,
            ImmutableArray<IPEndPoint> upstreamEndpoints,
            CancellationToken cancellationToken)
            => SendAsync(message, cancellationToken);
    }

    private sealed class StaticOptionsMonitor<T> : IOptionsMonitor<T>
    {
        public StaticOptionsMonitor(T current) => CurrentValue = current;
        public T CurrentValue { get; }
        public T Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }
}
