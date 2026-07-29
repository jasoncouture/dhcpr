using System.Collections.Immutable;
using System.Net;
using System.Security.Cryptography;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Validation;

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.UnitTests;

public class DnssecInsecureCnameAdTests
{
    [Fact]
    public async Task UnsignedCnameWithSignedTarget_IsInsecureWithoutAd()
    {
        // Mimics www.speedtest.net → CDN: insecure CNAME + signed A assembled client-facing.
        var (dnsKey, privateKey) = CreateEcdsaDnsKey("cloudflare.net");
        var cname = new DomainResourceRecord(
            new DomainLabels("www.speedtest.net"),
            DomainRecordType.CNAME,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(3600),
            new NameData(new DomainLabels("www.speedtest.net.cdn.cloudflare.net")));
        var a1 = new DomainResourceRecord(
            new DomainLabels("www.speedtest.net.cdn.cloudflare.net"),
            DomainRecordType.A,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(300),
            new IPAddressData(IPAddress.Parse("104.17.147.22")));
        var a2 = new DomainResourceRecord(
            new DomainLabels("www.speedtest.net.cdn.cloudflare.net"),
            DomainRecordType.A,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(300),
            new IPAddressData(IPAddress.Parse("104.17.148.22")));
        var aSig = SignRrset(privateKey, dnsKey, [a1, a2], DomainRecordType.A);

        var request = DomainMessage.CreateRequest("www.speedtest.net");
        var response = DomainMessage.CreateResponse(
            request,
            answers: [cname, a1, a2, aSig],
            responseCode: DomainResponseCode.NoError);

        var scope = new DnssecScope();
        scope.SetKeys(new AuthenticatedDnsKeySet { Zone = "cloudflare.net", Keys = [dnsKey] });

        var validator = new DnssecMessageValidator(
            new DnssecValidator(NullLogger<DnssecValidator>.Instance),
            new NoopInternalClient(),
            new StaticOptionsMonitor<DnsConfiguration>(new DnsConfiguration()),
            NullLogger<DnssecMessageValidator>.Instance);

        await validator.ValidateResponseAsync(
            new DomainMessageContext(null, null, request) { DnssecScope = scope },
            response,
            CancellationToken.None);

        Assert.Equal(DnssecValidationStatus.Insecure, scope.Status);
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
            300,
            (uint)now.AddDays(1).ToUnixTimeSeconds(),
            (uint)now.AddDays(-1).ToUnixTimeSeconds(),
            keyTag,
            dnsKey.Name,
            ImmutableArray<byte>.Empty);
        var prefix = DnssecRrsetVerifier.EncodeRrsigWithoutSignature(rrsigTemplate);
        var canonical = DnssecRrsetVerifier.BuildCanonicalRrset(rrset, 300);
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
            TimeSpan.FromSeconds(300),
            rrsig);
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
