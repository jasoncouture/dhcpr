using System.Net;

using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Server.Orleans.LiveQueries;

namespace Dhcpr.Server.LiveQueries;

/// <inheritdoc cref="ILiveQueryFilters"/>
public sealed class LiveQueryFilters : ILiveQueryFilters
{
    // Health checks use 127.0.0.1:0 / [::1]:0. Real loopback clients have an ephemeral port.
    public bool IsHealthCheckProbe(IPEndPoint? client) =>
        client is { Port: 0, Address: { } address } && IPAddress.IsLoopback(address);

    public bool IsHealthCheckProbe(DnsQueryEvent evt) =>
        IsHealthCheckProbe(evt.Client);

    public bool IsHealthCheckProbe(DnsQueryEventMessage evt)
    {
        if (evt.Client is null || !IPEndPoint.TryParse(evt.Client, out var client))
            return false;

        return IsHealthCheckProbe(client);
    }
}
