using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Extensions.Options;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class FileTlsServerCertificateProviderTests
{
    [Fact]
    public void GetCertificateReloadsWhenPemFilesChange()
    {
        var directory = Directory.CreateTempSubdirectory();
        try
        {
            var (certificatePath, keyPath) = WritePemPair(directory.FullName, "first");
            var provider = new FileTlsServerCertificateProvider(Monitor(new TlsConfiguration
            {
                Enabled = true,
                Listeners = ["127.0.0.1:853"],
                CertificatePath = certificatePath,
                PrivateKeyPath = keyPath
            }));
            provider.Refresh();

            var first = provider.GetCertificate();
            var firstThumbprint = first.Thumbprint;

            WritePemPair(directory.FullName, "second");
            File.SetLastWriteTimeUtc(certificatePath, DateTime.UtcNow.AddMinutes(1));
            File.SetLastWriteTimeUtc(keyPath, DateTime.UtcNow.AddMinutes(1));
            provider.Refresh();

            var second = provider.GetCertificate();
            Assert.NotEqual(firstThumbprint, second.Thumbprint);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    [Fact]
    public void GetCertificateReturnsCachedCertificateWhenFilesUnchanged()
    {
        var directory = Directory.CreateTempSubdirectory();
        try
        {
            var (certificatePath, keyPath) = WritePemPair(directory.FullName, "cached");
            var provider = new FileTlsServerCertificateProvider(Monitor(new TlsConfiguration
            {
                Enabled = true,
                Listeners = ["127.0.0.1:853"],
                CertificatePath = certificatePath,
                PrivateKeyPath = keyPath
            }));
            provider.Refresh();

            var first = provider.GetCertificate();
            var second = provider.GetCertificate();
            Assert.Same(first, second);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    private static (string CertificatePath, string KeyPath) WritePemPair(string directory, string commonName)
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

    private static IOptionsMonitor<T> Monitor<T>(T value)
    {
        var monitor = Substitute.For<IOptionsMonitor<T>>();
        monitor.CurrentValue.Returns(value);
        monitor.Get(Arg.Any<string?>()).Returns(value);
        return monitor;
    }
}
