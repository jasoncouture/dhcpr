using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

public interface IDnsResponseCache
{
    bool TryGet(DomainMessage request, out DomainMessage? response);
    bool TryGet(DomainMessage request, out DomainMessage? response, out DnssecValidationStatus securityStatus);
    void Set(DomainMessage request, DomainMessage response, DnssecValidationStatus securityStatus = DnssecValidationStatus.Unchecked);
    void UpdateSecurityStatus(DomainMessage request, DnssecValidationStatus securityStatus);
    void Remove(DomainMessage request);
    void Clear();
}
