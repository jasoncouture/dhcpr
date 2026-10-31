using Dhcpr.Dns.Core.Protocol;

namespace Dhcpr.Dns.Core.Validation;

/// <summary>DS digest over the canonical owner name and DNSKEY RDATA (RFC 4034 §5.1.4).</summary>
public interface ITrustAnchorDigest
{
    string Sha256(DomainResourceRecord dnsKeyRecord);
}
