using System.Net;

namespace Dhcpr.Dns.Core.Protocol.Processing.RateLimit;

public interface IUdpQueryRateLimiter
{
    UdpRateLimitAction Record(IPAddress? client, DomainLabels name, DomainRecordType type);
}
