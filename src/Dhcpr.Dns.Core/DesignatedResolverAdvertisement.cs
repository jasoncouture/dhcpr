using System.Net;
using System.Security.Cryptography.X509Certificates;

namespace Dhcpr.Dns.Core;

public static class DesignatedResolverAdvertisement
{
    public const string DohPathTemplate = "/dns-query{?dns}";
    public const string DotAlpn = "dot";
    public const string DohAlpn = "h2";

    public static DesignatedResolverConfiguration[] ForHost(string target, int dotPort, int dohPort)
        =>
        [
            new()
            {
                Priority = 1,
                Target = target,
                Alpn = [DotAlpn],
                Port = dotPort
            },
            new()
            {
                Priority = 2,
                Target = target,
                Alpn = [DohAlpn],
                Port = dohPort,
                DohPath = DohPathTemplate
            }
        ];

    public static DesignatedResolverConfiguration[] ForTls(
        TlsConfiguration tls,
        X509Certificate2 certificate)
    {
        var host = FirstHostName(certificate);
        if (host is null)
            return [];

        return ForHost(host, AdvertisedDotPort(tls), tls.HttpsPort);
    }

    public static string? FirstHostName(X509Certificate2 certificate)
    {
        foreach (var extension in certificate.Extensions)
        {
            if (extension is not X509SubjectAlternativeNameExtension san)
                continue;

            foreach (var name in san.EnumerateDnsNames())
            {
                if (IsAdvertisableHost(name))
                    return Normalize(name);
            }
        }

        var dnsName = certificate.GetNameInfo(X509NameType.DnsName, false);
        return IsAdvertisableHost(dnsName) ? Normalize(dnsName) : null;
    }

    public static int AdvertisedDotPort(TlsConfiguration tls)
    {
        foreach (var endPoint in tls.GetParsedListeners())
        {
            if (endPoint is IPEndPoint ip)
                return ip.Port;
        }

        return TlsConfiguration.DefaultPort;
    }

    private static bool IsAdvertisableHost(string? name)
        => !string.IsNullOrWhiteSpace(name) && !name.Contains('*', StringComparison.Ordinal);

    private static string Normalize(string name)
        => name.Trim().TrimEnd('.');
}
