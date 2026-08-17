using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.Validation;

public interface IDnssecMessageValidator
{
    void EnsureTrustAnchorsLoaded(DnssecScope scope);
    ValueTask ValidateResponseAsync(
        DomainMessageContext context,
        DomainMessage response,
        CancellationToken cancellationToken);
}
