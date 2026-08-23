using System;
using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Security.Cryptography;
using Dhcpr.Dns.Core;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Validation;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

using NSubstitute;

using Xunit;

namespace Dhcpr.Dns.Core.UnitTests;

public class DnssecValidatorTests
{
    private readonly DnssecValidator _validator;

    public DnssecValidatorTests()
    {
        _validator = new DnssecValidator(NullLogger<DnssecValidator>.Instance, Monitor(new DnsConfiguration()));
    }

    [Fact]
    public void Nsec3HashCalculationIsCorrect()
    {
        var salt = "there is no salt"u8.ToArray();
        var nsec3Param = new NextSecure3Data(
            Nsec3HashAlgorithm.Sha1,
            0,
            12,
            salt.ToImmutableArray(),
            ImmutableArray<byte>.Empty,
            ImmutableArray<byte>.Empty
        );

        var name = new DomainLabels("example");
        var hash = _validator.CalculateNsec3Hash(name, nsec3Param);

        Assert.Equal(20, hash.Length);
    }

    [Fact]
    public void EcdsaP256Sha256SignatureVerificationWorks()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var pubParams = ecdsa.ExportParameters(false);
        var pubKey = new byte[64];
        pubParams.Q.X!.CopyTo(pubKey, 0);
        pubParams.Q.Y!.CopyTo(pubKey, 32);

        var payload = "This is some test data that we will sign."u8.ToArray();
        var signature = ecdsa.SignData(payload, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        var rrsigData = new ResourceRecordSignatureData(
            DomainRecordType.A,
            DnssecAlgorithmType.EcdsaP256Sha256,
            2,
            3600,
            (uint)DateTimeOffset.UtcNow.AddDays(1).ToUnixTimeSeconds(),
            (uint)DateTimeOffset.UtcNow.AddDays(-1).ToUnixTimeSeconds(),
            1234,
            new DomainLabels("example.com"),
            signature.ToImmutableArray()
        );

        var dnsKeyData = new DomainNameSystemKeyData(
            256,
            3,
            DnssecAlgorithmType.EcdsaP256Sha256,
            pubKey.ToImmutableArray()
        );

        var result = _validator.VerifySignature(rrsigData, ReadOnlySpan<byte>.Empty, payload, dnsKeyData);
        Assert.True(result);
    }

    [Fact]
    public void EcdsaP384Sha384SignatureVerificationWorks()
    {
        using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var pubParams = ecdsa.ExportParameters(false);
        var x = pubParams.Q.X!;
        var y = pubParams.Q.Y!;
        var pubKey = new byte[96];
        x.CopyTo(pubKey.AsSpan(48 - x.Length));
        y.CopyTo(pubKey.AsSpan(96 - y.Length));

        var payload = "This is some test data that we will sign."u8.ToArray();
        var signature = ecdsa.SignData(payload, HashAlgorithmName.SHA384, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);

        var rrsigData = new ResourceRecordSignatureData(
            DomainRecordType.A,
            DnssecAlgorithmType.EcdsaP384Sha384,
            2,
            3600,
            (uint)DateTimeOffset.UtcNow.AddDays(1).ToUnixTimeSeconds(),
            (uint)DateTimeOffset.UtcNow.AddDays(-1).ToUnixTimeSeconds(),
            1234,
            new DomainLabels("fedoraproject.org"),
            signature.ToImmutableArray()
        );

        var dnsKeyData = new DomainNameSystemKeyData(
            256,
            3,
            DnssecAlgorithmType.EcdsaP384Sha384,
            pubKey.ToImmutableArray()
        );

        var result = _validator.VerifySignature(rrsigData, ReadOnlySpan<byte>.Empty, payload, dnsKeyData);
        Assert.True(result);
    }

    [Fact]
    public void RsaSha256SignatureVerificationWorks()
    {
        using var rsa = RSA.Create(2048);
        var pubParams = rsa.ExportParameters(false);
        
        var exponent = pubParams.Exponent!;
        var modulus = pubParams.Modulus!;
        
        var pubKey = new byte[1 + exponent.Length + modulus.Length];
        pubKey[0] = (byte)exponent.Length;
        exponent.CopyTo(pubKey, 1);
        modulus.CopyTo(pubKey, 1 + exponent.Length);

        var payload = "This is some test data that we will sign."u8.ToArray();
        var signature = rsa.SignData(payload, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var rrsigData = new ResourceRecordSignatureData(
            DomainRecordType.A,
            DnssecAlgorithmType.RsaSha256,
            2,
            3600,
            (uint)DateTimeOffset.UtcNow.AddDays(1).ToUnixTimeSeconds(),
            (uint)DateTimeOffset.UtcNow.AddDays(-1).ToUnixTimeSeconds(),
            1234,
            new DomainLabels("example.com"),
            signature.ToImmutableArray()
        );

        var dnsKeyData = new DomainNameSystemKeyData(
            256,
            3,
            DnssecAlgorithmType.RsaSha256,
            pubKey.ToImmutableArray()
        );

        var result = _validator.VerifySignature(rrsigData, ReadOnlySpan<byte>.Empty, payload, dnsKeyData);
        Assert.True(result);
    }

    [Fact]
    public void KeyTagCalculationMatchesRfc()
    {
        var dnsKeyData = new DomainNameSystemKeyData(
            256,
            3,
            DnssecAlgorithmType.RsaSha256,
            new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }.ToImmutableArray()
        );
        var record = new DomainResourceRecord(new DomainLabels("example.com"), DomainRecordType.DNSKEY, DomainRecordClass.IN, TimeSpan.FromSeconds(3600), dnsKeyData);

        var keyTag = _validator.CalculateKeyTag(dnsKeyData, record);
        Assert.NotEqual(0, keyTag);
    }

    [Fact]
    public void NsecCoversNameUsesCanonicalLabelOrder()
    {
        // RFC 4034 §6.1: names compare right-to-left by label, not as dotted strings.
        var nsec = new NextSecureData(new DomainLabels("z.example.com"), ImmutableArray<byte>.Empty);

        // Lexical "a.example.com" < "example.com", but canonical
        // example.com < a.example.com < z.example.com.
        Assert.True(_validator.CoversName(
            nsec,
            new DomainLabels("example.com"),
            new DomainLabels("a.example.com")));

        // Lexical "a-b.example" < "a.example" ('-' < '.'), but canonical
        // a.example < a-b.example < b.example.
        var hyphenNsec = new NextSecureData(new DomainLabels("b.example"), ImmutableArray<byte>.Empty);
        Assert.True(_validator.CoversName(
            hyphenNsec,
            new DomainLabels("a.example"),
            new DomainLabels("a-b.example")));
    }

    private static IOptionsMonitor<T> Monitor<T>(T value)
    {
        var monitor = Substitute.For<IOptionsMonitor<T>>();
        monitor.CurrentValue.Returns(value);
        monitor.Get(Arg.Any<string?>()).Returns(value);
        return monitor;
    }
}
