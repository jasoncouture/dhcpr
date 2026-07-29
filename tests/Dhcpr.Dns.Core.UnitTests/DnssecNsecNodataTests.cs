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

public class DnssecNsecNodataTests
{
    [Fact]
    public async Task NsecNodata_WithoutKeys_IsIndeterminateNotBogus()
    {
        var (dnsKey, privateKey) = CreateEcdsaDnsKey("cloudflare.net");
        var owner = new DomainLabels("cdn.cloudflare.net");
        var nsec = new DomainResourceRecord(
            owner,
            DomainRecordType.NSEC,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(1800),
            new NextSecureData(
                new DomainLabels("cdn0.cloudflare.net"),
                BuildTypeBitmap(DomainRecordType.A, DomainRecordType.RRSIG, DomainRecordType.NSEC)));
        var nsecSig = SignRrset(privateKey, dnsKey, [nsec], DomainRecordType.NSEC);

        var request = DomainMessage.CreateRequest("cdn.cloudflare.net", DomainRecordType.NS);
        var response = DomainMessage.CreateResponse(
            request,
            answers: [],
            authorities: [nsec, nsecSig],
            responseCode: DomainResponseCode.NoError);

        // Scope has trust anchors only — no cloudflare.net DNSKEY loaded.
        var scope = new DnssecScope();
        scope.LoadTrustAnchors([new TrustAnchorConfiguration()]);

        var validator = CreateValidator();
        await validator.ValidateResponseAsync(
            new DomainMessageContext(null, null, request) { DnssecScope = scope },
            response,
            CancellationToken.None);

        Assert.NotEqual(DnssecValidationStatus.Bogus, scope.Status);
    }

    [Fact]
    public async Task NsecNodata_WithKeys_IsSecure()
    {
        var (dnsKey, privateKey) = CreateEcdsaDnsKey("cloudflare.net");
        var owner = new DomainLabels("cdn.cloudflare.net");
        var nsec = new DomainResourceRecord(
            owner,
            DomainRecordType.NSEC,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(1800),
            new NextSecureData(
                new DomainLabels("cdn0.cloudflare.net"),
                BuildTypeBitmap(DomainRecordType.A, DomainRecordType.RRSIG, DomainRecordType.NSEC)));
        var nsecSig = SignRrset(privateKey, dnsKey, [nsec], DomainRecordType.NSEC);

        var request = DomainMessage.CreateRequest("cdn.cloudflare.net", DomainRecordType.NS);
        var response = DomainMessage.CreateResponse(
            request,
            answers: [],
            authorities: [nsec, nsecSig],
            responseCode: DomainResponseCode.NoError);

        var scope = new DnssecScope();
        scope.SetKeys(new AuthenticatedDnsKeySet { Zone = "cloudflare.net", Keys = [dnsKey] });

        var validator = CreateValidator();
        await validator.ValidateResponseAsync(
            new DomainMessageContext(null, null, request) { DnssecScope = scope },
            response,
            CancellationToken.None);

        Assert.Equal(DnssecValidationStatus.Secure, scope.Status);
    }

    private static DnssecMessageValidator CreateValidator()
    {
        var options = Options.Create(new DnsConfiguration());
        var monitor = new StaticOptionsMonitor<DnsConfiguration>(options.Value);
        return new DnssecMessageValidator(
            new DnssecValidator(NullLogger<DnssecValidator>.Instance, monitor),
            new NoopInternalClient(),
            monitor,
            NullLogger<DnssecMessageValidator>.Instance);
    }

    private static (DomainResourceRecord DnsKey, ECDsa PrivateKey) CreateEcdsaDnsKey(string zone)
    {
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pub = ecdsa.ExportParameters(false);
        var pubKey = new byte[64];
        pub.Q.X!.CopyTo(pubKey, 0);
        pub.Q.Y!.CopyTo(pubKey, 32);
        var data = new DomainNameSystemKeyData(256, 3, DnssecAlgorithmType.EcdsaP256Sha256, pubKey.ToImmutableArray());
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
        DomainResourceRecord dnsKey,
        IReadOnlyList<DomainResourceRecord> rrset,
        DomainRecordType typeCovered)
    {
        var crypto = new DnssecValidator(NullLogger<DnssecValidator>.Instance);
        var keyData = (DomainNameSystemKeyData)dnsKey.Data;
        var keyTag = crypto.CalculateKeyTag(keyData, dnsKey);
        var now = DateTimeOffset.UtcNow;
        var rrsigTemplate = new ResourceRecordSignatureData(
            typeCovered,
            DnssecAlgorithmType.EcdsaP256Sha256,
            (byte)rrset[0].Name.Count,
            1800,
            (uint)now.AddDays(1).ToUnixTimeSeconds(),
            (uint)now.AddDays(-1).ToUnixTimeSeconds(),
            keyTag,
            dnsKey.Name,
            ImmutableArray<byte>.Empty);
        var prefix = DnssecRrsetVerifier.EncodeRrsigWithoutSignature(rrsigTemplate);
        var canonical = DnssecRrsetVerifier.BuildCanonicalRrset(rrset, 1800);
        var payload = new byte[prefix.Length + canonical.Length];
        prefix.CopyTo(payload, 0);
        canonical.CopyTo(payload, prefix.Length);
        var signature = privateKey.SignData(
            payload, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        var rrsig = rrsigTemplate with { Signature = signature.ToImmutableArray() };
        return new DomainResourceRecord(
            rrset[0].Name,
            DomainRecordType.RRSIG,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(1800),
            rrsig);
    }

    private static ImmutableArray<byte> BuildTypeBitmap(params DomainRecordType[] types)
    {
        // Minimal window-0 bitmap covering the listed types (sufficient for unit tests).
        var max = types.Max(static t => (int)t);
        var bytes = new byte[(max / 8) + 1];
        foreach (var type in types)
        {
            var bit = (int)type;
            bytes[bit / 8] |= (byte)(0x80 >> (bit % 8));
        }

        return new byte[] { 0, (byte)bytes.Length }.Concat(bytes).ToImmutableArray();
    }

    private sealed class NoopInternalClient : IInternalDomainClient
    {
        public ValueTask<DomainMessage> SendAsync(DomainMessage message, CancellationToken cancellationToken)
            => ValueTask.FromResult(DomainMessage.CreateResponse(
                message, DomainResourceRecords.Empty, DomainResponseCode.ServerFailure));

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

    private sealed class StaticOptionsMonitor<T>(T current) : IOptionsMonitor<T>
    {
        public T CurrentValue { get; } = current;
        public T Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<T, string?> listener) => null;
    }
}
