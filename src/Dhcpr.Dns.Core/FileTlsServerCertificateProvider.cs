using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core;

public sealed class FileTlsServerCertificateProvider : ITlsServerCertificateProvider
{
    private readonly IOptionsMonitor<TlsConfiguration> _options;
    private readonly Lock _sync = new();
    private SslStreamCertificateContext? _context;
    private DateTime _certificateWriteTime;
    private DateTime _keyWriteTime;

    public FileTlsServerCertificateProvider(IOptionsMonitor<TlsConfiguration> options)
    {
        _options = options;
    }

    public X509Certificate2 GetCertificate()
        => GetServerCertificateContext().TargetCertificate;

    public SslStreamCertificateContext GetServerCertificateContext()
        => _context ?? throw new InvalidOperationException("TLS certificate is not loaded.");

    public void Refresh()
    {
        var config = _options.CurrentValue;
        if (!config.Enabled)
            return;

        var certificateWriteTime = File.GetLastWriteTimeUtc(config.CertificatePath);
        var keyWriteTime = File.GetLastWriteTimeUtc(config.PrivateKeyPath);
        if (_context is not null &&
            certificateWriteTime == _certificateWriteTime &&
            keyWriteTime == _keyWriteTime)
            return;

        lock (_sync)
        {
            if (_context is not null &&
                certificateWriteTime == _certificateWriteTime &&
                keyWriteTime == _keyWriteTime)
                return;

            config = _options.CurrentValue;
            using var loaded = X509Certificate2.CreateFromPemFile(config.CertificatePath, config.PrivateKeyPath);
            var exported = X509CertificateLoader.LoadPkcs12(
                loaded.Export(X509ContentType.Pfx),
                (string?)null);
            var context = SslStreamCertificateContext.Create(
                exported,
                LoadIntermediates(config.CertificatePath, exported),
                offline: true);
            _certificateWriteTime = certificateWriteTime;
            _keyWriteTime = keyWriteTime;
            _context = context;
        }
    }

    private static X509Certificate2Collection? LoadIntermediates(string certificatePath, X509Certificate2 leaf)
    {
        var parsed = new X509Certificate2Collection();
        parsed.ImportFromPem(File.ReadAllText(certificatePath));
        var extra = new X509Certificate2Collection();
        foreach (var certificate in parsed)
        {
            if (!string.Equals(certificate.Thumbprint, leaf.Thumbprint, StringComparison.Ordinal))
                extra.Add(certificate);
        }

        return extra.Count == 0 ? null : extra;
    }
}
