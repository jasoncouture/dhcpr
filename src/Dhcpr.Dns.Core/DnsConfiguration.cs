using System.Net;
using System.Diagnostics.CodeAnalysis;

using Dhcpr.Core;

namespace Dhcpr.Dns.Core;

public sealed class DnsConfiguration : IValidateSelf
{
    public RootServerConfiguration RootServers { get; set; } = new();
    public Dictionary<string, string[]> Routes { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    private Dictionary<string, IPEndPoint[]> _parsedRoutes = new(StringComparer.OrdinalIgnoreCase);

    public IReadOnlyDictionary<string, IPEndPoint[]> GetParsedRoutes() => _parsedRoutes;
    
    public TrustAnchorConfiguration[] TrustAnchors { get; set; } = { new TrustAnchorConfiguration() };

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
        if (RootServers is null || !RootServers.Validate())
        {
            error = "DNS:RootServers is invalid";
            return false;
        }

        if (Routes is null || Routes.Count == 0)
        {
            error = "DNS:Routes is missing or empty";
            return false;
        }

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

        if (!_parsedRoutes.ContainsKey("."))
        {
            _parsedRoutes["."] = RootServers.Addresses.GetEndPoints();
        }

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


        if (TrustAnchors is not null)
        {
            foreach (var anchor in TrustAnchors)
            {
                if (!anchor.TryValidate(out error))
                {
                    error = $"DNS:TrustAnchors contains an invalid entry: {error}";
                    return false;
                }
            }
        }

        error = null;
        return true;
    }
}
