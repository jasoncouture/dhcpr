using System.Net;
using System.Diagnostics.CodeAnalysis;

using Dhcpr.Core;

using Microsoft.Extensions.Configuration;

namespace Dhcpr.Dns.Core;

public sealed class DnsConfiguration : IValidateSelf
{
    public RootServerConfiguration RootServers { get; set; } = new();

    /// <summary>
    /// Conditional forwarder map: longest domain suffix → upstream nameserver endpoints.
    /// Empty means all names fall through to recursive resolution.
    /// </summary>
    public Dictionary<string, string[]> Routes { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    private Dictionary<string, IPEndPoint[]> _parsedRoutes = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyDictionary<string, IPEndPoint[]> GetParsedRoutes() => _parsedRoutes;

    public TrustAnchorConfiguration[] TrustAnchors { get; set; } = { new TrustAnchorConfiguration() };

    /// <summary>DNSSEC validation enable/disable and algorithm policy.</summary>
    public DnssecConfiguration Dnssec { get; set; } = new();

    /// <summary>ASP.NET health check: resolve these domains through the DNS pipeline.</summary>
    public DnsHealthCheckConfiguration HealthCheck { get; set; } = new();

    [ConfigurationKeyName("DOH")]
    public DnsOverHttpConfiguration DnsOverHttp { get; set; } = new();

    public DnsListenEndpoint[] GetListenEndpoints() => ListenAddresses.GetListenEndpoints();

    /// <summary>
    /// Listen URIs for the DNS server.
    /// Examples: <c>udp://127.0.0.1:53</c>, <c>tcp://localhost:5353</c>,
    /// <c>interface://enp2s0:53/</c> (all addresses on that NIC, UDP+TCP).
    /// Set per environment in appsettings (e.g. Development uses 65353).
    /// </summary>
    public string[] ListenAddresses { get; set; } = Array.Empty<string>();

    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract",
        Justification = "Values are set by configuration binding")]
    public bool Validate() => TryValidate(out _);

    public bool TryValidate([NotNullWhen(false)] out string? error)
    {
        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (RootServers is null || !RootServers.Validate())
        {
            error = "DNS:RootServers is invalid";
            return false;
        }

        // ReSharper disable once NullCoalescingConditionIsAlwaysNotNullAccordingToAPIContract
        Routes ??= new Dictionary<string, string[]>(StringComparer.OrdinalIgnoreCase);
        _parsedRoutes = new Dictionary<string, IPEndPoint[]>(StringComparer.OrdinalIgnoreCase);

        foreach (var route in Routes)
        {
            if (route.Value is null || route.Value.Length == 0)
            {
                error = $"DNS:Routes[\"{route.Key}\"] is missing or empty";
                return false;
            }

            var endpoints = new IPEndPoint[route.Value.Length];
            for (var i = 0; i < route.Value.Length; i++)
            {
                if (!route.Value[i].TryGetEndPoint(53, out var endpoint))
                {
                    error = $"DNS:Routes[\"{route.Key}\"] contains an invalid endpoint URI: {route.Value[i]}";
                    return false;
                }

                endpoints[i] = (IPEndPoint)endpoint;
            }

            _parsedRoutes[route.Key] = endpoints;
        }

        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (ListenAddresses is null || ListenAddresses.Length == 0)
        {
            error = "DNS:ListenAddresses is missing or empty (set per environment in appsettings)";
            return false;
        }

        if (!ListenAddresses.AreAllListenAddressesValid())
        {
            error = "DNS:ListenAddresses contains an invalid listen URI";
            return false;
        }


        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (TrustAnchors is not null)
        {
            foreach (var anchor in TrustAnchors)
            {
                if (anchor.TryValidate(out error))
                {
                    continue;
                }

                error = $"DNS:TrustAnchors contains an invalid entry: {error}";
                return false;
            }
        }

        Dnssec ??= new DnssecConfiguration();
        if (!Dnssec.TryValidate(out error))
            return false;

        HealthCheck ??= new DnsHealthCheckConfiguration();
        if (!HealthCheck.TryValidate(out error))
            return false;

        DnsOverHttp ??= new DnsOverHttpConfiguration();
        if (!DnsOverHttp.Validate())
        {
            error = "DNS:DOH:MaxRequestBytes must be between 1 and 65535";
            return false;
        }

        error = null;
        return true;
    }
}
