using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Dhcpr.Dns.Core.UnitTests;

public class DesignatedResolverAdvertisementTests
{
    [Fact]
    public void ForHostAdvertisesDotThenDoh()
    {
        var advertised = DesignatedResolverAdvertisement.ForHost("dns.example.com", 853, 443);

        Assert.Equal(2, advertised.Length);
        Assert.Equal(1, advertised[0].Priority);
        Assert.Equal(["dot"], advertised[0].Alpn);
        Assert.Equal(853, advertised[0].Port);
        Assert.Null(advertised[0].DohPath);
        Assert.Equal(2, advertised[1].Priority);
        Assert.Equal(["h2"], advertised[1].Alpn);
        Assert.Equal(443, advertised[1].Port);
        Assert.Equal(DesignatedResolverAdvertisement.DohPathTemplate, advertised[1].DohPath);
    }

    [Fact]
    public void FirstHostNameSkipsWildcardSan()
    {
        using var certificate = SelfSignedWithSans("*.example.com", "dns.example.com");

        Assert.Equal("dns.example.com", DesignatedResolverAdvertisement.FirstHostName(certificate));
    }

    private static X509Certificate2 SelfSignedWithSans(params string[] dnsNames)
    {
        using var key = ECDsa.Create();
        var request = new CertificateRequest("CN=wildcard.example.com", key, HashAlgorithmName.SHA256);
        var san = new SubjectAlternativeNameBuilder();
        foreach (var name in dnsNames)
            san.AddDnsName(name);
        request.CertificateExtensions.Add(san.Build());
        return request.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddDays(30));
    }
}
