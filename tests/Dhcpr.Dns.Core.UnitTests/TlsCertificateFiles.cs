using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace Dhcpr.Dns.Core.UnitTests;

internal static class TlsCertificateFiles
{
    public static (string CertificatePath, string KeyPath) WritePemPair(string directory, string commonName)
    {
        using var key = ECDsa.Create();
        var request = new CertificateRequest($"CN={commonName}", key, HashAlgorithmName.SHA256);
        using var certificate = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddDays(30));

        var certificatePath = Path.Combine(directory, "tls.crt");
        var keyPath = Path.Combine(directory, "tls.key");
        File.WriteAllText(certificatePath, certificate.ExportCertificatePem());
        File.WriteAllText(keyPath, key.ExportPkcs8PrivateKeyPem());
        return (certificatePath, keyPath);
    }
}
