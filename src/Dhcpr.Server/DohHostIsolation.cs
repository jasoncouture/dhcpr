using System.Security.Cryptography.X509Certificates;

using Dhcpr.Dns.Core;

namespace Dhcpr.Server;

public static class DohHostIsolation
{
    public static bool IsDnsQueryPath(PathString path)
        => path.StartsWithSegments(
               DnsOverHttpEndpointExtensions.DnsQueryPath,
               StringComparison.OrdinalIgnoreCase,
               out var rest)
           && (string.IsNullOrEmpty(rest.Value) || rest.Value == "/");

    /// <summary>
    /// True when this request must 404: isolation is on, the Host is a DoH
    /// name, and the path is not <c>/dns-query</c>.
    /// </summary>
    public static bool ShouldReturnNotFound(
        PathString path,
        HostString requestHost,
        DnsConfiguration dns,
        TlsConfiguration tls,
        X509Certificate2? certificate)
    {
        if (!dns.DnsOverHttp.IsolateHost)
            return false;

        if (IsDnsQueryPath(path))
            return false;

        var hosts = AdvertisedHosts(dns, tls, certificate);
        return hosts.Count > 0 && HostMatches(requestHost, hosts);
    }

    public static bool HostMatches(HostString requestHost, IReadOnlyList<string> dohHosts)
    {
        var host = Normalize(requestHost.Host);
        if (host is null)
            return false;

        for (var i = 0; i < dohHosts.Count; i++)
        {
            if (host.Equals(Normalize(dohHosts[i]), StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    public static IReadOnlyList<string> AdvertisedHosts(
        DnsConfiguration dns,
        TlsConfiguration tls,
        X509Certificate2? certificate)
    {
        var designated = dns.DesignatedResolvers;
        if (designated is { Length: > 0 })
        {
            var hosts = new List<string>(designated.Length);
            foreach (var resolver in designated)
            {
                var target = Normalize(resolver.Target);
                if (target is not null)
                    hosts.Add(target);
            }

            return hosts;
        }

        if (!tls.Enabled || certificate is null)
            return [];

        var fromCert = DesignatedResolverAdvertisement.FirstHostName(certificate);
        return fromCert is null ? [] : [fromCert];
    }

    public static string? Normalize(string? host)
    {
        if (string.IsNullOrWhiteSpace(host))
            return null;

        return host.Trim().TrimEnd('.');
    }
}
