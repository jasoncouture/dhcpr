using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Security.Cryptography;
using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Parser;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core.Validation;

public sealed class DnssecValidator : IDnssecValidator
{
    private readonly ILogger<DnssecValidator> _logger;

    public DnssecValidator(ILogger<DnssecValidator> logger)
    {
        _logger = logger;
    }

    public bool VerifySignature(ResourceRecordSignatureData rrsig, ReadOnlySpan<byte> rrsigWireDataExcludingSignature, ReadOnlySpan<byte> canonicalRrsetData, DomainNameSystemKeyData dnsKey)
    {
        if (rrsig.Algorithm != dnsKey.Algorithm)
            return false;

        // Signature covers: rrsigWireDataExcludingSignature + canonicalRrsetData
        var payloadSize = rrsigWireDataExcludingSignature.Length + canonicalRrsetData.Length;
        var payload = ArrayPool<byte>.Shared.Rent(payloadSize);
        try
        {
            rrsigWireDataExcludingSignature.CopyTo(payload.AsSpan());
            canonicalRrsetData.CopyTo(payload.AsSpan(rrsigWireDataExcludingSignature.Length));
            var payloadSpan = payload.AsSpan(0, payloadSize);

            return dnsKey.Algorithm switch
            {
                8 => VerifyRsaSha256(payloadSpan, rrsig.Signature.AsSpan(), dnsKey.PublicKey.AsSpan()),
                13 => VerifyEcdsaP256Sha256(payloadSpan, rrsig.Signature.AsSpan(), dnsKey.PublicKey.AsSpan()),
                _ => false // Unsupported algorithm
            };
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to verify signature for algorithm {Algorithm}", rrsig.Algorithm);
            return false;
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(payload);
        }
    }

    private static bool VerifyRsaSha256(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyData)
    {
        // RFC 3110 Section 2: RSA Public Key representation
        // length(Exponent) is 1 or 3 bytes (depending on first byte).
        if (publicKeyData.Length < 1) return false;
        
        int exponentLength = publicKeyData[0];
        int offset = 1;
        if (exponentLength == 0)
        {
            if (publicKeyData.Length < 3) return false;
            exponentLength = BinaryPrimitives.ReadUInt16BigEndian(publicKeyData[1..3]);
            offset = 3;
        }

        if (publicKeyData.Length < offset + exponentLength) return false;
        var exponent = publicKeyData.Slice(offset, exponentLength);
        offset += exponentLength;
        var modulus = publicKeyData[offset..];

        using var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters
        {
            Exponent = exponent.ToArray(),
            Modulus = modulus.ToArray()
        });

        return rsa.VerifyData(data, signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
    }

    private static bool VerifyEcdsaP256Sha256(ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature, ReadOnlySpan<byte> publicKeyData)
    {
        // RFC 6605: ECDSA P-256 public key is 64 bytes (X and Y). Signature is 64 bytes (R and S).
        if (publicKeyData.Length != 64 || signature.Length != 64) return false;

        using var ecdsa = ECDsa.Create(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            Q = new ECPoint
            {
                X = publicKeyData[..32].ToArray(),
                Y = publicKeyData[32..].ToArray()
            }
        });

        // The BCL ECDsa.VerifyData expects IEEE P1363 format (which is just R || S for P-256 in standard format)
        return ecdsa.VerifyData(data, signature, HashAlgorithmName.SHA256, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    public ushort CalculateKeyTag(DomainNameSystemKeyData dnsKey, DomainResourceRecord dnsKeyRecord)
    {
        var rdataSize = dnsKey.EstimatedSize;
        var buffer = ArrayPool<byte>.Shared.Rent(rdataSize);
        try
        {
            using var dict = DictionaryPool<string, int>.Default.Get();
            var span = new DnsParsingSpan(dict, buffer);
            dnsKey.WriteTo(ref span);
            
            // WriteTo prepends the 2-byte RDLENGTH, we skip it
            var rdata = buffer.AsSpan(2, span.Offset - 2);

            if (dnsKey.Algorithm == 1) // RSA/MD5 (deprecated, but keeping rule for correctness)
            {
                if (rdata.Length < 5) return 0;
                return BinaryPrimitives.ReadUInt16BigEndian(rdata[^3..^1]);
            }

            // RFC 4034 Appendix B: Key Tag Calculation
            long ac = 0;
            for (var i = 0; i < rdata.Length; i++)
            {
                ac += (i & 1) != 0 ? rdata[i] : rdata[i] << 8;
            }
            ac += (ac >> 16) & 0xFFFF;
            return (ushort)(ac & 0xFFFF);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public bool VerifyDelegationSigner(DelegationSignerData ds, DomainResourceRecord dnsKeyRecord)
    {
        var size = dnsKeyRecord.EstimatedSize;
        var buffer = ArrayPool<byte>.Shared.Rent(size * 2);
        try
        {
            var span = buffer.AsSpan();
            DomainResourceRecordCanonicalizationExtensions.EncodeCanonicalName(ref span, dnsKeyRecord.Name);
            var offset = buffer.Length - span.Length;
            
            using (var dict = DictionaryPool<string, int>.Default.Get())
            {
                var parsingSpan = new DnsParsingSpan(dict, buffer.AsSpan(offset));
                dnsKeyRecord.Data.WriteTo(ref parsingSpan);
                // Strip the RDLENGTH (2 bytes)
                var rdataLen = parsingSpan.Offset - 2;
                buffer.AsSpan(offset + 2, rdataLen).CopyTo(buffer.AsSpan(offset));
                offset += rdataLen;
            }

            var payload = buffer.AsSpan(0, offset);

            byte[] digest = ds.DigestType switch
            {
                1 => SHA1.HashData(payload), // SHA-1
                2 => SHA256.HashData(payload), // SHA-256
                4 => SHA384.HashData(payload), // SHA-384
                _ => Array.Empty<byte>()
            };

            return digest.AsSpan().SequenceEqual(ds.Digest.AsSpan());
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public byte[] CalculateNsec3Hash(DomainLabels name, NextSecure3Data nsec3Parameters)
    {
        if (nsec3Parameters.HashAlgorithm != 1) // Only SHA-1 is standard for NSEC3
            return Array.Empty<byte>();

        // Canonicalize name
        var buffer = ArrayPool<byte>.Shared.Rent(255);
        try
        {
            var span = buffer.AsSpan();
            DomainResourceRecordCanonicalizationExtensions.EncodeCanonicalName(ref span, name);
            var nameLen = buffer.Length - span.Length;
            
            var payloadSize = nameLen + nsec3Parameters.Salt.Length;
            var payload = ArrayPool<byte>.Shared.Rent(payloadSize);
            try
            {
                buffer.AsSpan(0, nameLen).CopyTo(payload);
                nsec3Parameters.Salt.CopyTo(payload.AsSpan(nameLen));
                
                var hash = SHA1.HashData(payload.AsSpan(0, payloadSize));
                for (var i = 0; i < nsec3Parameters.Iterations; i++)
                {
                    var iterPayload = ArrayPool<byte>.Shared.Rent(hash.Length + nsec3Parameters.Salt.Length);
                    try
                    {
                        hash.CopyTo(iterPayload.AsSpan());
                        nsec3Parameters.Salt.CopyTo(iterPayload.AsSpan(hash.Length));
                        hash = SHA1.HashData(iterPayload.AsSpan(0, hash.Length + nsec3Parameters.Salt.Length));
                    }
                    finally
                    {
                        ArrayPool<byte>.Shared.Return(iterPayload);
                    }
                }
                return hash;
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(payload);
            }
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public bool CoversName(NextSecureData nsec, DomainLabels nsecOwner, DomainLabels nameToVerify)
    {
        // Simple canonical ordering check: nsecOwner < nameToVerify < nsec.NextDomainName
        // Wrapping is allowed (if nsecOwner > nsec.NextDomainName, it's the last record in zone)
        var owner = nsecOwner.ToString().ToLowerInvariant();
        var next = nsec.NextDomainName.ToString().ToLowerInvariant();
        var target = nameToVerify.ToString().ToLowerInvariant();

        var ownerToTarget = string.CompareOrdinal(owner, target);
        var targetToNext = string.CompareOrdinal(target, next);

        if (string.CompareOrdinal(owner, next) < 0)
            return ownerToTarget < 0 && targetToNext < 0;
        
        // Wrap-around case
        return ownerToTarget < 0 || targetToNext < 0;
    }

    public bool CoversHash(NextSecure3Data nsec3, ReadOnlySpan<byte> nsec3OwnerHash, ReadOnlySpan<byte> hashToVerify)
    {
        var nextHash = nsec3.NextHashedOwnerName.AsSpan();
        
        var ownerToTarget = nsec3OwnerHash.SequenceCompareTo(hashToVerify);
        var targetToNext = hashToVerify.SequenceCompareTo(nextHash);

        if (nsec3OwnerHash.SequenceCompareTo(nextHash) < 0)
            return ownerToTarget < 0 && targetToNext < 0;

        // Wrap-around case
        return ownerToTarget < 0 || targetToNext < 0;
    }
}