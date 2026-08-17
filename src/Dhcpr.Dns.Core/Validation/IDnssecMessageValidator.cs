using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.Validation;

public interface IDnssecMessageValidator
{
    /// <summary>
    /// Loads configured trust anchors into <paramref name="scope"/> when the root delegation is missing.
    /// </summary>
    void EnsureTrustAnchorsLoaded(DnssecScope scope);

    /// <summary>
    /// Validates <paramref name="response"/> into <paramref name="context"/>'s <see cref="DnssecScope"/>
    /// (trust-anchor → DS → DNSKEY → RRSIG, plus NSEC for NXDOMAIN/NODATA).
    /// </summary>
    ValueTask ValidateResponseAsync(
        DomainMessageContext context,
        DomainMessage response,
        CancellationToken cancellationToken);
}
