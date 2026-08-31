using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

/// <summary>
/// Process-bound: drops the shared response cache when DNS options change.
/// </summary>
public sealed class DnsConfigurationCacheInvalidator : IHostedService, IDisposable
{
    private readonly IDisposable? _subscription;

    public DnsConfigurationCacheInvalidator(
        IOptionsMonitor<DnsConfiguration> options,
        IDnsResponseCache cache)
    {
        _subscription = options.OnChange(_ => cache.Clear());
    }

    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    public void Dispose() => _subscription?.Dispose();
}
