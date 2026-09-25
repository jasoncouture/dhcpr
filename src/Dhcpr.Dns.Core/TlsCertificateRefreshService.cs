using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core;

public sealed partial class TlsCertificateRefreshService : BackgroundService
{
    public static readonly TimeSpan RefreshInterval = TimeSpan.FromSeconds(15);

    private readonly FileTlsServerCertificateProvider _certificates;
    private readonly ILogger<TlsCertificateRefreshService> _logger;

    public TlsCertificateRefreshService(
        ITlsServerCertificateProvider certificates,
        ILogger<TlsCertificateRefreshService> logger)
    {
        _certificates = (FileTlsServerCertificateProvider)certificates;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                _certificates.Refresh();
            }
            catch (Exception exception) when (!stoppingToken.IsCancellationRequested && HasCertificate())
            {
                LogRefreshFailed(_logger, exception);
            }

            await Task.Delay(RefreshInterval, stoppingToken).ConfigureAwait(false);
        }
    }

    private bool HasCertificate()
    {
        try
        {
            _certificates.GetServerCertificateContext();
            return true;
        }
        catch (InvalidOperationException)
        {
            return false;
        }
    }

    [LoggerMessage(Level = LogLevel.Error, Message = "TLS certificate refresh failed")]
    private static partial void LogRefreshFailed(ILogger logger, Exception exception);
}
