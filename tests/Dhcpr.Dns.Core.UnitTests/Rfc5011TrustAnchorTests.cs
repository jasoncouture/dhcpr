using System.Collections.Immutable;
using System.Security.Cryptography;
using System.Text.Json;

using Dhcpr.Core;
using Dhcpr.Dns.Core;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Validation;

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class Rfc5011TrustAnchorTests
{
    private static readonly DateTimeOffset T0 = new(2026, 10, 11, 0, 0, 0, TimeSpan.Zero);
    private static readonly byte[] PublicKey = [1, 2, 3, 4];

    [Fact]
    public void NewSepKey_StaysPending_UntilHoldDownExpires()
    {
        var state = new TrustAnchorState();
        var first = Rfc5011TrustAnchorUpdate.Apply(state, [Key(flags: 257, tag: 99)], T0);
        Assert.True(first.Changed);
        Assert.Equal(TrustAnchorEventKind.Pending, first.Events[0].Kind);
        Assert.Equal(TrustAnchorAcceptance.Pending, state.Entries[0].State);

        var early = Rfc5011TrustAnchorUpdate.Apply(
            state,
            [Key(flags: 257, tag: 99)],
            T0 + Rfc5011Timing.AddHoldDown - TimeSpan.FromSeconds(1));
        Assert.False(early.Changed);
        Assert.Equal(TrustAnchorAcceptance.Pending, state.Entries[0].State);

        var due = Rfc5011TrustAnchorUpdate.Apply(
            state,
            [Key(flags: 257, tag: 99)],
            T0 + Rfc5011Timing.AddHoldDown);
        Assert.Equal(TrustAnchorEventKind.Trusted, due.Events[0].Kind);
        Assert.Equal(TrustAnchorAcceptance.Trusted, state.Entries[0].State);
    }

    [Fact]
    public void PendingKey_MissingFromAuthenticatedSet_IsDropped()
    {
        var state = new TrustAnchorState();
        Rfc5011TrustAnchorUpdate.Apply(state, [Key(flags: 257, tag: 99)], T0);

        var dropped = Rfc5011TrustAnchorUpdate.Apply(state, [], T0.AddDays(1));
        Assert.Equal(TrustAnchorEventKind.PendingDropped, dropped.Events[0].Kind);
        Assert.Empty(state.Entries);

        Rfc5011TrustAnchorUpdate.Apply(state, [Key(flags: 257, tag: 99)], T0.AddDays(2));
        Assert.Equal(T0.AddDays(2), state.Entries[0].PendingSince);
    }

    [Fact]
    public void TrustedKey_MissingFromAuthenticatedSet_StaysTrusted()
    {
        var state = Trusted(tag: 99);
        var result = Rfc5011TrustAnchorUpdate.Apply(state, [], T0.AddDays(1));
        Assert.False(result.Changed);
        Assert.Equal(TrustAnchorAcceptance.Trusted, state.Entries[0].State);
    }

    [Fact]
    public void RevokedKey_IsRemoved_AndNotReadded()
    {
        var state = Trusted(tag: 99);
        var revoked = Rfc5011TrustAnchorUpdate.Apply(state, [Key(flags: 257 | 0x0080, tag: 99)], T0);
        Assert.Equal(TrustAnchorEventKind.Revoked, revoked.Events[0].Kind);
        Assert.Empty(state.Entries);
        Assert.Contains("AA", state.RevokedDigests);

        var again = Rfc5011TrustAnchorUpdate.Apply(state, [Key(flags: 257, tag: 99)], T0.AddDays(1));
        Assert.False(again.Changed);
        Assert.Empty(state.Entries);
    }

    [Fact]
    public void ZoneSigningKey_IsIgnored()
    {
        var state = new TrustAnchorState();
        var result = Rfc5011TrustAnchorUpdate.Apply(state, [Key(flags: 256, tag: 50)], T0);
        Assert.False(result.Changed);
        Assert.Empty(state.Entries);
    }

    [Fact]
    public void ActiveAnchors_IncludeBothRootKsks()
    {
        using var dir = new TempDir();
        var store = Store(dir, new DnsConfiguration());
        var anchors = store.GetActiveAnchors();
        Assert.Contains(anchors, anchor => anchor.KeyTag == TrustAnchorConfiguration.Ksk2017KeyTag);
        Assert.Contains(anchors, anchor => anchor.KeyTag == TrustAnchorConfiguration.Ksk2024KeyTag);
    }

    [Fact]
    public void RevokedDigest_IsNotResurrectedFromConfiguration()
    {
        using var dir = new TempDir();
        var digest = new TrustAnchorConfiguration().DigestHex;
        File.WriteAllText(
            Path.Combine(dir.Path, ApplicationConfiguration.TrustAnchorFileName),
            JsonSerializer.Serialize(new TrustAnchorState { RevokedDigests = [digest] }));

        var store = Store(dir, new DnsConfiguration());
        var anchors = store.GetActiveAnchors();
        Assert.DoesNotContain(anchors, anchor => anchor.KeyTag == TrustAnchorConfiguration.Ksk2017KeyTag);
        Assert.Contains(anchors, anchor => anchor.KeyTag == TrustAnchorConfiguration.Ksk2024KeyTag);
    }

    [Fact]
    public void PendingKey_IsNotUsedForValidation()
    {
        using var dir = new TempDir();
        File.WriteAllText(
            Path.Combine(dir.Path, ApplicationConfiguration.TrustAnchorFileName),
            """
            {
              "Entries": [
                {
                  "Zone": ".",
                  "Algorithm": 8,
                  "KeyTag": 1,
                  "DigestType": 2,
                  "DigestHex": "ABCD",
                  "State": "Pending",
                  "PendingSince": "2026-10-01T00:00:00Z"
                }
              ]
            }
            """);

        var store = Store(dir, new DnsConfiguration { TrustAnchors = [] });
        Assert.DoesNotContain(store.GetActiveAnchors(), anchor => anchor.KeyTag == 1);
    }

    [Fact]
    public void Sha256Digest_MatchesDelegationSignerCheck()
    {
        var (record, _) = CreateKey();
        var digest = TrustAnchorDigest.Sha256(record);
        var crypto = new DnssecValidator(NullLogger<DnssecValidator>.Instance, Monitor(new DnsConfiguration()));
        var ds = new DelegationSignerData(
            crypto.CalculateKeyTag((DomainNameSystemKeyData)record.Data, record),
            DnssecAlgorithmType.EcdsaP256Sha256,
            DelegationSignerDigestType.Sha256,
            Convert.FromHexString(digest).ToImmutableArray());
        Assert.True(crypto.VerifyDelegationSigner(ds, record));
    }

    [Fact]
    public async Task Accept_RequiresASignatureFromATrustedKey()
    {
        using var dir = new TempDir();
        var (record, privateKey) = CreateKey();
        var digest = TrustAnchorDigest.Sha256(record);
        var crypto = new DnssecValidator(NullLogger<DnssecValidator>.Instance, Monitor(new DnsConfiguration()));
        var store = Store(dir, new DnsConfiguration
        {
            TrustAnchors =
            [
                new TrustAnchorConfiguration
                {
                    KeyTag = crypto.CalculateKeyTag((DomainNameSystemKeyData)record.Data, record),
                    Algorithm = (byte)DnssecAlgorithmType.EcdsaP256Sha256,
                    DigestType = (byte)DelegationSignerDigestType.Sha256,
                    DigestHex = digest
                }
            ]
        });

        var signature = Sign(privateKey, crypto, record);
        var signed = await store.AcceptDnsKeySetAsync([record], [signature], crypto, DateTimeOffset.UtcNow, CancellationToken.None);
        Assert.Equal(TrustAnchorRefreshKind.Updated, signed.Kind);

        signature = signature with
        {
            Data = ((ResourceRecordSignatureData)signature.Data) with
            {
                Signature = [0, 1, 2, 3]
            }
        };
        var rejected = await store.AcceptDnsKeySetAsync([record], [signature], crypto, DateTimeOffset.UtcNow, CancellationToken.None);
        Assert.Equal(TrustAnchorRefreshKind.NotAuthenticated, rejected.Kind);
    }

    private static TrustAnchorKeyObservation Key(ushort flags, ushort tag)
        => new(PublicKey, flags, 8, tag, "AA");

    private static TrustAnchorState Trusted(ushort tag)
        => new()
        {
            Entries =
            [
                new TrustAnchorRecord
                {
                    PublicKeyBase64 = Convert.ToBase64String(PublicKey),
                    KeyTag = tag,
                    Algorithm = 8,
                    DigestType = 2,
                    DigestHex = "AA",
                    State = TrustAnchorAcceptance.Trusted
                }
            ]
        };

    private static TrustAnchorStore Store(TempDir dir, DnsConfiguration dns)
        => new(
            Monitor(dns),
            Monitor(new ApplicationConfiguration { DataPath = dir.Path }),
            NullLogger<TrustAnchorStore>.Instance);

    private static (DomainResourceRecord Record, ECDsa Key) CreateKey()
    {
        var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var point = ecdsa.ExportParameters(false);
        var publicKey = new byte[64];
        point.Q.X!.CopyTo(publicKey, 0);
        point.Q.Y!.CopyTo(publicKey, 32);
        var data = new DomainNameSystemKeyData(257, 3, DnssecAlgorithmType.EcdsaP256Sha256, publicKey.ToImmutableArray());
        var record = new DomainResourceRecord(
            DomainLabels.Empty,
            DomainRecordType.DNSKEY,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(300),
            data);
        return (record, ecdsa);
    }

    private static DomainResourceRecord Sign(ECDsa privateKey, DnssecValidator crypto, DomainResourceRecord dnsKey)
    {
        var now = DateTimeOffset.UtcNow;
        var unsigned = new ResourceRecordSignatureData(
            DomainRecordType.DNSKEY,
            DnssecAlgorithmType.EcdsaP256Sha256,
            0,
            300,
            (uint)now.AddDays(1).ToUnixTimeSeconds(),
            (uint)now.AddDays(-1).ToUnixTimeSeconds(),
            crypto.CalculateKeyTag((DomainNameSystemKeyData)dnsKey.Data, dnsKey),
            DomainLabels.Empty,
            ImmutableArray<byte>.Empty);
        var prefix = DnssecRrsetVerifier.EncodeRrsigWithoutSignature(unsigned);
        var canonical = DnssecRrsetVerifier.BuildCanonicalRrset([dnsKey], 300, 0);
        var payload = new byte[prefix.Length + canonical.Length];
        prefix.CopyTo(payload, 0);
        canonical.CopyTo(payload, prefix.Length);
        var signature = privateKey.SignData(payload, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
        return new DomainResourceRecord(
            DomainLabels.Empty,
            DomainRecordType.RRSIG,
            DomainRecordClass.IN,
            TimeSpan.FromSeconds(300),
            unsigned with { Signature = signature.ToImmutableArray() });
    }

    private static IOptionsMonitor<T> Monitor<T>(T value)
    {
        var monitor = Substitute.For<IOptionsMonitor<T>>();
        monitor.CurrentValue.Returns(value);
        return monitor;
    }

    private sealed class TempDir : IDisposable
    {
        public TempDir() => Path = Directory.CreateTempSubdirectory("dhcpr-ta-").FullName;
        public string Path { get; }
        public void Dispose() => Directory.Delete(Path, recursive: true);
    }
}
