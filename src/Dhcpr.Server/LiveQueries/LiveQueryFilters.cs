using System.Net;

using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Server.Orleans.LiveQueries;

namespace Dhcpr.Server.LiveQueries;

/// <summary>
/// Shared drop rules for live-query fan-out (UI store and WebSocket).
/// </summary>
internal static class LiveQueryFilters
{
    // Health checks use 127.0.0.1:0 / [::1]:0. Real loopback clients have an ephemeral port.
    public static bool IsHealthCheckProbe(IPEndPoint? client) =>
        client is { Port: 0, Address: { } address } && IPAddress.IsLoopback(address);

    public static bool IsHealthCheckProbe(DnsQueryEvent evt) =>
        IsHealthCheckProbe(evt.Client);

    public static bool IsHealthCheckProbe(DnsQueryEventMessage evt)
    {
        if (evt.Client is null || !IPEndPoint.TryParse(evt.Client, out var client))
            return false;

        return IsHealthCheckProbe(client);
    }
}
