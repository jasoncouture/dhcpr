using System.Net;

using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Server.Orleans.LiveQueries;

namespace Dhcpr.Server.LiveQueries;

/// <summary>
/// Shared drop rules for live-query fan-out (UI store and WebSocket).
/// </summary>
public interface ILiveQueryFilters
{
    bool IsHealthCheckProbe(IPEndPoint? client);

    bool IsHealthCheckProbe(DnsQueryEvent evt);

    bool IsHealthCheckProbe(DnsQueryEventMessage evt);
}
