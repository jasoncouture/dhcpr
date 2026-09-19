using System.Net;
using System.Diagnostics.CodeAnalysis;

using Dhcpr.Core;
using Dhcpr.Dns.Core.ConfiguredRecords;

using Microsoft.Extensions.Configuration;

namespace Dhcpr.Dns.Core;

public sealed class DnsConfiguration : IValidateSelf
{
    public RootServerConfiguration RootServers { get; set; } = new();

    /// <summary>
    /// Conditional forwarder map: longest domain suffix → upstream nameservers,
    /// optionally limited to client CIDRs.
    /// Empty means all names fall through to recursive resolution.
    /// </summary>
    public Dictionary<string, DnsRouteConfiguration> Routes { get; set; } = new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Sparse overlay records (A/AAAA/CNAME/NS). Misses fall through to DynDNS / zones / forward.
    /// Empty <c>Clients</c> on a record means any client.
    /// </summary>
    public DnsRecordConfiguration[] Records { get; set; } = [];

    private Dictionary<string, ParsedDnsRoute> _parsedRoutes = new(StringComparer.OrdinalIgnoreCase);
    private ParsedConfiguredRecordIndex _parsedRecords = ParsedConfiguredRecordIndex.Empty;

    public IReadOnlyDictionary<string, ParsedDnsRoute> GetParsedRoutes() => _parsedRoutes;

    public ParsedConfiguredRecordIndex GetParsedRecords() => _parsedRecords;

    /// <summary>
    /// Domain suffixes or regexes that always receive NXDOMAIN (no cache / upstream).
    /// A suffix matches the name and any subdomain (e.g. <c>example.com</c> → <c>*.example.com</c>).
    /// A line is a regex when it starts with <c>/</c> or contains
    /// <c>^ $ + * ? [ ( { | \</c> (e.g. <c>.+\..+\.localdomain$</c>).
    /// </summary>
    public string[] BlackholeDomains { get; set; } = Array.Empty<string>();

    private BlackholeRuleSet _blackholeRules = BlackholeRuleSet.Empty;

    public BlackholeRuleSet GetBlackholeRules() => _blackholeRules;

    /// <summary>
    /// RFC 9462 designated resolvers advertised as SVCB at <c>_dns.resolver.arpa</c>.
    /// Empty → NODATA for that name; <c>resolver.arpa</c> is still served locally and never forwarded.
    /// </summary>
    public DesignatedResolverConfiguration[] DesignatedResolvers { get; set; } = [];

    public TrustAnchorConfiguration[] TrustAnchors { get; set; } = { new TrustAnchorConfiguration() };

    /// <summary>DNSSEC validation enable/disable and algorithm policy.</summary>
    public DnssecConfiguration Dnssec { get; set; } = new();

    /// <summary>ASP.NET health check: resolve these domains through the DNS pipeline.</summary>
    public DnsHealthCheckConfiguration HealthCheck { get; set; } = new();

    [ConfigurationKeyName("DOH")]
    public DnsOverHttpConfiguration DnsOverHttp { get; set; } = new();

    /// <summary>Two-tier sliding-window limit for classic DNS over UDP.</summary>
    public UdpRateLimitConfiguration UdpRateLimit { get; set; } = new();

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

        var routes = Routes ?? new Dictionary<string, DnsRouteConfiguration>(StringComparer.OrdinalIgnoreCase);
        _parsedRoutes = new Dictionary<string, ParsedDnsRoute>(StringComparer.OrdinalIgnoreCase);

        foreach (var route in routes)
        {
            if (!DnsRouteConfiguration.TryNormalizeSuffix(route.Key, out var suffix))
            {
                error = $"DNS:Routes[\"{route.Key}\"] is not a domain suffix";
                return false;
            }

            var config = route.Value ?? new DnsRouteConfiguration();
            config.Upstreams ??= [];
            config.Clients ??= [];

            if (config.Upstreams.Length == 0)
            {
                error = $"DNS:Routes[\"{suffix}\"] is missing or empty";
                return false;
            }

            var endpoints = new IPEndPoint[config.Upstreams.Length];
            for (var i = 0; i < config.Upstreams.Length; i++)
            {
                if (!config.Upstreams[i].TryGetEndPoint(53, out var endpoint))
                {
                    error = $"DNS:Routes[\"{suffix}\"] contains an invalid endpoint URI: {config.Upstreams[i]}";
                    return false;
                }

                endpoints[i] = (IPEndPoint)endpoint;
            }

            var clients = new IPNetwork[config.Clients.Length];
            for (var i = 0; i < config.Clients.Length; i++)
            {
                if (!ParsedDnsRoute.TryParseClientNetwork(config.Clients[i], out var network))
                {
                    error = $"DNS:Routes[\"{suffix}\"].Clients[{i}] is not a CIDR or IP: {config.Clients[i]}";
                    return false;
                }

                clients[i] = network;
            }

            if (!_parsedRoutes.TryAdd(suffix, new ParsedDnsRoute(endpoints, clients)))
            {
                error = $"DNS:Routes[\"{suffix}\"] is duplicated";
                return false;
            }
        }

        Records ??= [];
        if (!ParsedConfiguredRecordIndex.TryBuild(Records, out var parsedRecords, out error))
            return false;
        _parsedRecords = parsedRecords;

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

        UdpRateLimit ??= new UdpRateLimitConfiguration();
        if (!UdpRateLimit.TryValidate(out error))
            return false;

        BlackholeDomains ??= Array.Empty<string>();
        for (var i = 0; i < BlackholeDomains.Length; i++)
        {
            var domain = BlackholeDomains[i]?.Trim() ?? "";
            if (!BlackholeRuleSet.LooksLikeRegex(domain))
                domain = domain.TrimEnd('.');
            if (string.IsNullOrWhiteSpace(domain))
            {
                error = $"DNS:BlackholeDomains[{i}] is empty";
                return false;
            }

            BlackholeDomains[i] = domain;
        }

        if (!BlackholeRuleSet.TryCreate(BlackholeDomains, out error, out _blackholeRules))
            return false;

        DesignatedResolvers ??= [];
        for (var i = 0; i < DesignatedResolvers.Length; i++)
        {
            var designated = DesignatedResolvers[i] ?? new DesignatedResolverConfiguration();
            DesignatedResolvers[i] = designated;
            if (!designated.TryValidate(i, out error))
                return false;
        }

        error = null;
        return true;
    }
}
