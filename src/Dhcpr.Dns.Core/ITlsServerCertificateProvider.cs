using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace Dhcpr.Dns.Core;

public interface ITlsServerCertificateProvider
{
    X509Certificate2 GetCertificate();

    SslStreamCertificateContext GetServerCertificateContext();
}
