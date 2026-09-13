using System.Net;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public interface IUdpQueryRateLimiter
{
    UdpRateLimitAction Record(IPAddress? client, DomainLabels name);
}
