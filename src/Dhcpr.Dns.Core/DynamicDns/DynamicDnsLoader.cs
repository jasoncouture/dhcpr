using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core.DynamicDns;

public sealed class DynamicDnsLoader : IHostedService
{
    private readonly IDynamicDnsStore _store;
    private readonly ILogger<DynamicDnsLoader> _logger;

    public DynamicDnsLoader(IDynamicDnsStore store, ILogger<DynamicDnsLoader> logger)
    {
        _store = store;
        _logger = logger;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _store.LoadFromDisk();
        _logger.LogDebug("Dynamic DNS store ready");
        return Task.CompletedTask;
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
}
