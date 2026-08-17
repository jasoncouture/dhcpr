using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core.DynamicDns;

public sealed partial class DynamicDnsLoader : IHostedService
{
    private readonly IDynamicDnsStore _store;
    private readonly ILogger<DynamicDnsLoader> _logger;

    public DynamicDnsLoader(IDynamicDnsStore store, ILogger<DynamicDnsLoader> logger)
    {
        _store = store;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await Task.Yield();
        _store.LoadFromDisk();
        LogStoreReady(_logger);
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        await Task.Yield();
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "Dynamic DNS store ready")]
    private static partial void LogStoreReady(ILogger logger);
}
