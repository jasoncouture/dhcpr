using System.Collections.Immutable;
using System.Net;
using System.Security.Cryptography;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Validation;

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class DnssecNsec3Tests
{
    private static readonly byte[] _salt = Convert.FromHexString("AABBCCDD");

    [Fact]
    public void Base32Hex_RoundTrips()
    {
        var data = Convert.FromHexString("DEADBEEF00112233");
        var encoded = DnssecBase32Hex.Encode(data);
        Span<byte> decoded = stackalloc byte[32];
        Assert.True(DnssecBase32Hex.TryDecode(encoded, decoded, out var len));
        Assert.True(data.AsSpan().SequenceEqual(decoded[..len]));
    }

    [Fact]
    public void TypeBitMaps_ContainsTypes()
    {
        var maps = DnssecTypeBitMaps.FromTypes(DomainRecordType.NS, DomainRecordType.SOA);
        Assert.True(DnssecTypeBitMaps.Contains(maps, DomainRecordType.NS));
        Assert.True(DnssecTypeBitMaps.Contains(maps, DomainRecordType.SOA));
        Assert.False(DnssecTypeBitMaps.Contains(maps, DomainRecordType.A));
    }

    [Fact]
    public void Rfc5155_AppendixA_HashVector()
    {
        // RFC 5155 Appendix A: H(example) with salt aabbccdd, iterations 12.
        var parameters = new NextSecure3Data(
            Nsec3HashAlgorithm.Sha1,
            1,
            12,
            _salt.ToImmutableArray(),
            ImmutableArray<byte>.Empty,
            ImmutableArray<byte>.Empty);

        var crypto = new DnssecValidator(NullLogger<DnssecValidator>.Instance);
        var hash = crypto.CalculateNsec3Hash(new DomainLabels("example"), parameters);
        var encoded = DnssecBase32Hex.Encode(hash);
        Assert.Equal("0P9MHAVEQVM6T7VBL5LOP2U3T2RP3TOM", encoded);
    }

    [Fact]
    public async Task Nsec3_NodataProof_IsSecure()
    {
        var (dnsKey, privateKey) = CreateEcdsaDnsKey("example.com");
        var crypto = new DnssecValidator(NullLogger<DnssecValidator>.Instance);
        var parameters = CreateParams(flags: 0);

        var qname = new DomainLabels("www.example.com");
        var hash = crypto.CalculateNsec3Hash(qname, parameters);
        var owner = Nsec3Owner(hash, "example.com");
        var nsec3 = new DomainResourceRecord(
            owner,
            DomainRecordType.NSEC3,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(300),
            parameters with
            {
                NextHashedOwnerName = Enumerable.Repeat((byte)0xFF, 20).ToImmutableArray(),
                TypeBitMaps = DnssecTypeBitMaps.FromTypes(DomainRecordType.AAAA) // A absent
            });
        var rrsig = SignRrset(privateKey, dnsKey, [nsec3], DomainRecordType.NSEC3);

        var request = DomainMessage.CreateRequest(qname.ToString(), DomainRecordType.A);
        var response = DomainMessage.CreateResponse(
            request,
            answers: [],
            authorities: [nsec3, rrsig],
            responseCode: DomainResponseCode.NoError);

        var scope = CreateScope(dnsKey);
        var validator = CreateValidator();
        var context = new DomainMessageContext(null, null, request) { DnssecScope = scope };
        await validator.ValidateResponseAsync(context, response, CancellationToken.None);

        Assert.Equal(DnssecValidationStatus.Secure, scope.Status);
    }

    [Fact]
    public async Task Nsec3_NxdomainProof_IsSecure()
    {
        var (dnsKey, privateKey) = CreateEcdsaDnsKey("example.com");
        var crypto = new DnssecValidator(NullLogger<DnssecValidator>.Instance);
        var parameters = CreateParams(flags: 0);

        var closest = new DomainLabels("example.com");
        var qname = new DomainLabels("noexist.example.com");
        var wildcard = new DomainLabels("*.example.com");

        var closestHash = crypto.CalculateNsec3Hash(closest, parameters);
        var closestNsec3 = new DomainResourceRecord(
            Nsec3Owner(closestHash, "example.com"),
            DomainRecordType.NSEC3,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(300),
            parameters with
            {
                NextHashedOwnerName = IncrementHash(closestHash).ToImmutableArray(),
                TypeBitMaps = DnssecTypeBitMaps.FromTypes(
                    DomainRecordType.NS, DomainRecordType.SOA, DomainRecordType.DNSKEY, DomainRecordType.NSEC3PARAM)
            });

        // Cover-all span for next-closer and wildcard hashes.
        var coverOwnerHash = new byte[20];
        var coverNsec3 = new DomainResourceRecord(
            Nsec3Owner(coverOwnerHash, "example.com"),
            DomainRecordType.NSEC3,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(300),
            parameters with
            {
                NextHashedOwnerName = Enumerable.Repeat((byte)0xFF, 20).ToImmutableArray(),
                TypeBitMaps = DnssecTypeBitMaps.FromTypes(DomainRecordType.NS)
            });

        // Ensure cover does not accidentally exact-match closest (closestHash != 0).
        Assert.False(closestHash.AsSpan().SequenceEqual(coverOwnerHash));
        Assert.NotNull(DnssecNsec3Proof.FindCover(
            crypto,
            DnssecNsec3Proof.Collect([closestNsec3, coverNsec3]),
            crypto.CalculateNsec3Hash(qname, parameters)));
        Assert.NotNull(DnssecNsec3Proof.FindCover(
            crypto,
            DnssecNsec3Proof.Collect([closestNsec3, coverNsec3]),
            crypto.CalculateNsec3Hash(wildcard, parameters)));

        var records = new List<DomainResourceRecord> { closestNsec3, coverNsec3 };
        records.Add(SignRrset(privateKey, dnsKey, [closestNsec3], DomainRecordType.NSEC3));
        records.Add(SignRrset(privateKey, dnsKey, [coverNsec3], DomainRecordType.NSEC3));

        var request = DomainMessage.CreateRequest(qname.ToString(), DomainRecordType.A);
        var response = DomainMessage.CreateResponse(
            request,
            answers: [],
            authorities: records.ToImmutableArray(),
            responseCode: DomainResponseCode.NameError);

        var scope = CreateScope(dnsKey);
        var validator = CreateValidator();
        var context = new DomainMessageContext(null, null, request) { DnssecScope = scope };
        await validator.ValidateResponseAsync(context, response, CancellationToken.None);

        Assert.Equal(DnssecValidationStatus.Secure, scope.Status);
    }

    [Fact]
    public async Task Nsec3_OptOutCover_IsInsecure()
    {
        var (dnsKey, privateKey) = CreateEcdsaDnsKey("example.com");
        var crypto = new DnssecValidator(NullLogger<DnssecValidator>.Instance);
        var parameters = CreateParams(flags: DnssecNsec3Proof.OptOutFlag);

        var closest = new DomainLabels("example.com");
        var qname = new DomainLabels("unsigned-child.example.com");

        var closestHash = crypto.CalculateNsec3Hash(closest, parameters);
        var closestNsec3 = new DomainResourceRecord(
            Nsec3Owner(closestHash, "example.com"),
            DomainRecordType.NSEC3,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(300),
            parameters with
            {
                Flags = 0,
                NextHashedOwnerName = IncrementHash(closestHash).ToImmutableArray(),
                TypeBitMaps = DnssecTypeBitMaps.FromTypes(DomainRecordType.NS, DomainRecordType.SOA)
            });

        var coverOwnerHash = new byte[20];
        var coverNsec3 = new DomainResourceRecord(
            Nsec3Owner(coverOwnerHash, "example.com"),
            DomainRecordType.NSEC3,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(300),
            parameters with
            {
                Flags = DnssecNsec3Proof.OptOutFlag,
                NextHashedOwnerName = Enumerable.Repeat((byte)0xFF, 20).ToImmutableArray(),
                TypeBitMaps = DnssecTypeBitMaps.FromTypes(DomainRecordType.NS)
            });

        var authorities = ImmutableArray.Create(
            closestNsec3,
            coverNsec3,
            SignRrset(privateKey, dnsKey, [closestNsec3], DomainRecordType.NSEC3),
            SignRrset(privateKey, dnsKey, [coverNsec3], DomainRecordType.NSEC3));

        var request = DomainMessage.CreateRequest(qname.ToString(), DomainRecordType.A);
        var response = DomainMessage.CreateResponse(
            request,
            answers: [],
            authorities: authorities,
            responseCode: DomainResponseCode.NameError);

        var scope = CreateScope(dnsKey);
        var validator = CreateValidator();
        var context = new DomainMessageContext(null, null, request) { DnssecScope = scope };
        await validator.ValidateResponseAsync(context, response, CancellationToken.None);

        Assert.Equal(DnssecValidationStatus.Insecure, scope.Status);
    }

    [Fact]
    public async Task Referral_DoesNotRequireNegativeProof()
    {
        var (dnsKey, privateKey) = CreateEcdsaDnsKey("example.com");
        var ns = new DomainResourceRecord(
            new DomainLabels("child.example.com"),
            DomainRecordType.NS,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(300),
            new NameData(new DomainLabels("ns.child.example.com")));
        var nsSig = SignRrset(privateKey, dnsKey, [ns], DomainRecordType.NS);

        var request = DomainMessage.CreateRequest("www.child.example.com", DomainRecordType.A);
        var response = DomainMessage.CreateResponse(
            request,
            answers: [],
            authorities: [ns, nsSig],
            responseCode: DomainResponseCode.NoError);

        var scope = CreateScope(dnsKey);
        var validator = CreateValidator();
        var context = new DomainMessageContext(null, null, request) { DnssecScope = scope };
        await validator.ValidateResponseAsync(context, response, CancellationToken.None);

        Assert.Equal(DnssecValidationStatus.Secure, scope.Status);
    }

    private static NextSecure3Data CreateParams(byte flags) => new(
        Nsec3HashAlgorithm.Sha1,
        flags,
        12,
        _salt.ToImmutableArray(),
        ImmutableArray<byte>.Empty,
        ImmutableArray<byte>.Empty);

    private static DomainLabels Nsec3Owner(byte[] hash, string zone)
        => new($"{DnssecBase32Hex.Encode(hash)}.{zone}");

    private static byte[] IncrementHash(byte[] hash)
    {
        var next = (byte[])hash.Clone();
        for (var i = next.Length - 1; i >= 0; i--)
        {
            if (next[i] < 0xFF)
            {
                next[i]++;
                return next;
            }

            next[i] = 0;
        }

        return Enumerable.Repeat((byte)0xFF, hash.Length).ToArray();
    }

    private static DnssecScope CreateScope(DomainResourceRecord dnsKey)
    {
        var scope = new DnssecScope();
        scope.SetKeys(new AuthenticatedDnsKeySet
        {
            Zone = "example.com",
            Keys = [dnsKey]
        });
        scope.SetDelegation(new AuthenticatedDelegation
        {
            Zone = "example.com",
            Digests =
            [
                new DelegationSignerData(
                    CalculateKeyTag(dnsKey),
                    DnssecAlgorithmType.EcdsaP256Sha256,
                    DelegationSignerDigestType.Sha256,
                    Convert.FromHexString(ComputeDsDigestHex(dnsKey)).ToImmutableArray())
            ],
            IsTrustAnchor = true
        });
        // Pretend we already observed something so Combine works from Unchecked.
        return scope;
    }

    private static DnssecMessageValidator CreateValidator()
    {
        var crypto = new DnssecValidator(NullLogger<DnssecValidator>.Instance);
        var options = Monitor(new DnsConfiguration
        {
            TrustAnchors = [new TrustAnchorConfiguration()]
        });
        return new DnssecMessageValidator(
            crypto,
            new NoopInternalClient(),
            options,
            NullLogger<DnssecMessageValidator>.Instance);
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
            new DomainLabels(zone),
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

    private static IOptionsMonitor<T> Monitor<T>(T value)
    {
        var monitor = Substitute.For<IOptionsMonitor<T>>();
        monitor.CurrentValue.Returns(value);
        monitor.Get(Arg.Any<string?>()).Returns(value);
        return monitor;
    }
}
