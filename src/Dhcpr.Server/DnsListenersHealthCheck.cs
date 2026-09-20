using Dhcpr.Dns.Core;
using Dhcpr.Dns.Core.Protocol.Processing;

using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace Dhcpr.Server;

/// <summary>
/// Unhealthy until every DNS socket is bound and, when TLS is on, Kestrel is listening for HTTPS.
/// </summary>
public sealed class DnsListenersHealthCheck : IHealthCheck
{
    public const string Name = "dns_listeners";

    private readonly IDnsListenerReadiness _dns;
    private readonly IOptionsMonitor<TlsConfiguration> _tls;
    private readonly IServer _server;

    public DnsListenersHealthCheck(
        IDnsListenerReadiness dns,
        IOptionsMonitor<TlsConfiguration> tls,
        IServer server)
    {
        _dns = dns;
        _tls = tls;
        _server = server;
    }

    public Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken)
    {
        if (!_dns.AllBound)
        {
            var pending = string.Join(", ", _dns.Pending);
            return Task.FromResult(HealthCheckResult.Unhealthy(
                pending.Length == 0
                    ? "DNS listeners have not started"
                    : $"DNS listeners not bound: {pending}"));
        }

        var tls = _tls.CurrentValue;
        if (tls.Enabled && !HttpsIsListening(tls.HttpsPort))
        {
            return Task.FromResult(HealthCheckResult.Unhealthy(
                $"HTTPS :{tls.HttpsPort} is not listening"));
        }

        return Task.FromResult(HealthCheckResult.Healthy("All listeners are bound"));
    }

    private bool HttpsIsListening(int port)
    {
        var addresses = _server.Features.Get<IServerAddressesFeature>()?.Addresses;
        if (addresses is null)
            return false;

        foreach (var address in addresses)
        {
            if (IsHttpsOnPort(address, port))
                return true;
        }

        return false;
    }

    internal static bool IsHttpsOnPort(string address, int port)
    {
        if (!address.StartsWith("https:", StringComparison.OrdinalIgnoreCase))
            return false;

        var normalized = address.Replace("://+", "://0.0.0.0", StringComparison.Ordinal);
        if (Uri.TryCreate(normalized, UriKind.Absolute, out var uri))
            return uri.Port == port;

        return address.Contains($":{port}", StringComparison.Ordinal);
    }
}
