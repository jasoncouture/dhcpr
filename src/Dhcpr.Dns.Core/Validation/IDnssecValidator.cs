using System;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Validation;

public interface IDnssecValidator
{
    /// <summary>
    /// Verifies the cryptographic signature of an RRSET against a given DNSKEY.
    /// </summary>
    bool VerifySignature(ResourceRecordSignatureData rrsig, ReadOnlySpan<byte> rrsigWireDataExcludingSignature, ReadOnlySpan<byte> canonicalRrsetData, DomainNameSystemKeyData dnsKey);

    /// <summary>
    /// Calculates the Key Tag for a given DNSKEY per RFC 4034 Appendix B.
    /// </summary>
    ushort CalculateKeyTag(DomainNameSystemKeyData dnsKey, DomainResourceRecord dnsKeyRecord);

    /// <summary>
    /// Verifies if a Delegation Signer (DS) record correctly matches the given DNSKEY.
    /// </summary>
    bool VerifyDelegationSigner(DelegationSignerData ds, DomainResourceRecord dnsKeyRecord);

    /// <summary>
    /// Computes the NSEC3 hash for a given domain name using the provided parameters.
    /// </summary>
    byte[] CalculateNsec3Hash(DomainLabels name, NextSecure3Data nsec3Parameters);

    /// <summary>
    /// Checks if a domain name is covered by an NSEC record's span.
    /// </summary>
    bool CoversName(NextSecureData nsec, DomainLabels nsecOwner, DomainLabels nameToVerify);

    /// <summary>
    /// Checks if an NSEC3 hash is covered by an NSEC3 record's span.
    /// </summary>
    bool CoversHash(NextSecure3Data nsec3, ReadOnlySpan<byte> nsec3OwnerHash, ReadOnlySpan<byte> hashToVerify);
}
