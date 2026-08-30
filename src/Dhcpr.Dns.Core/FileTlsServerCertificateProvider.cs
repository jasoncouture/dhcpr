using System.Security.Cryptography.X509Certificates;

using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core;

public sealed class FileTlsServerCertificateProvider : ITlsServerCertificateProvider, IDisposable
{
    private readonly IOptionsMonitor<TlsConfiguration> _options;
    private readonly Lock _sync = new();
    private X509Certificate2? _current;
    private DateTime _certificateWriteTime;
    private DateTime _keyWriteTime;

    public FileTlsServerCertificateProvider(IOptionsMonitor<TlsConfiguration> options)
    {
        _options = options;
    }

    public X509Certificate2 GetCertificate()
    {
        var config = _options.CurrentValue;
        var certificateWriteTime = File.GetLastWriteTimeUtc(config.CertificatePath);
        var keyWriteTime = File.GetLastWriteTimeUtc(config.PrivateKeyPath);

        lock (_sync)
        {
            if (_current is not null &&
                certificateWriteTime == _certificateWriteTime &&
                keyWriteTime == _keyWriteTime)
                return _current;

            using var loaded = X509Certificate2.CreateFromPemFile(config.CertificatePath, config.PrivateKeyPath);
            var exported = X509CertificateLoader.LoadPkcs12(
                loaded.Export(X509ContentType.Pfx),
                (string?)null);

            _current?.Dispose();
            _current = exported;
            _certificateWriteTime = certificateWriteTime;
            _keyWriteTime = keyWriteTime;
            return exported;
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            _current?.Dispose();
            _current = null;
        }
    }
}
