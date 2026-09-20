using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

/// <summary>
/// Process-bound: drops the shared response cache when DNS or TLS options
/// change (resolver.arpa SVCB is built from designated resolvers / the cert).
/// </summary>
public sealed class DnsConfigurationCacheInvalidator : IHostedService, IDisposable
{
    private readonly IDisposable? _dnsSubscription;
    private readonly IDisposable? _tlsSubscription;

    public DnsConfigurationCacheInvalidator(
        IOptionsMonitor<DnsConfiguration> dns,
        IOptionsMonitor<TlsConfiguration> tls,
        IDnsResponseCache cache)
    {
        _dnsSubscription = dns.OnChange(_ => cache.Clear());
        _tlsSubscription = tls.OnChange(_ => cache.Clear());
    }

    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public void Dispose()
    {
        _dnsSubscription?.Dispose();
        _tlsSubscription?.Dispose();
    }
}
