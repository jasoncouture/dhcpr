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
            var (certificatePath, keyPath) = TlsCertificateFiles.WritePemPair(directory.FullName, "first");
            ITlsServerCertificateProvider provider = new FileTlsServerCertificateProvider(Monitor(new TlsConfiguration
            {
                Enabled = true,
                Listeners = ["127.0.0.1:853"],
                CertificatePath = certificatePath,
                PrivateKeyPath = keyPath
            }));

            var first = provider.GetCertificate();
            var firstThumbprint = first.Thumbprint;

            TlsCertificateFiles.WritePemPair(directory.FullName, "second");
            File.SetLastWriteTimeUtc(certificatePath, DateTime.UtcNow.AddMinutes(1));
            File.SetLastWriteTimeUtc(keyPath, DateTime.UtcNow.AddMinutes(1));

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
            var (certificatePath, keyPath) = TlsCertificateFiles.WritePemPair(directory.FullName, "cached");
            ITlsServerCertificateProvider provider = new FileTlsServerCertificateProvider(Monitor(new TlsConfiguration
            {
                Enabled = true,
                Listeners = ["127.0.0.1:853"],
                CertificatePath = certificatePath,
                PrivateKeyPath = keyPath
            }));

            var first = provider.GetCertificate();
            var second = provider.GetCertificate();
            Assert.Same(first, second);
        }
        finally
        {
            directory.Delete(recursive: true);
        }
    }

    private static IOptionsMonitor<T> Monitor<T>(T value)
    {
        var monitor = Substitute.For<IOptionsMonitor<T>>();
        monitor.CurrentValue.Returns(value);
        monitor.Get(Arg.Any<string?>()).Returns(value);
        return monitor;
    }
}
