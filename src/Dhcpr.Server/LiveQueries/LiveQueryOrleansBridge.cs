using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Server.Orleans.LiveQueries;

using MessagePipe;

using Microsoft.Extensions.Hosting;

namespace Dhcpr.Server.LiveQueries;

/// <summary>
/// Subscribes to the cluster-wide Orleans live-query hub and republishes into MessagePipe
/// so <see cref="LiveQueryStore"/> (and any other in-process subscribers) receive events.
/// </summary>
public sealed class LiveQueryOrleansBridge : IHostedService
{
    private readonly IGrainFactory _grainFactory;
    private readonly IAsyncPublisher<DnsQueryEvent> _publisher;
    private readonly ILogger<LiveQueryOrleansBridge> _logger;

    private ILiveQueryObserver? _observer;
    private ILiveQueryHubGrain? _hub;

    public LiveQueryOrleansBridge(
        IGrainFactory grainFactory,
        IAsyncPublisher<DnsQueryEvent> publisher,
        ILogger<LiveQueryOrleansBridge> logger)
    {
        _grainFactory = grainFactory;
        _publisher = publisher;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        var observer = new HubObserver(_publisher);
        _observer = _grainFactory.CreateObjectReference<ILiveQueryObserver>(observer);
        _hub = _grainFactory.GetGrain<ILiveQueryHubGrain>(Guid.Empty);
        await _hub.Subscribe(_observer, cancellationToken);
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (_hub is not null && _observer is not null)
        {
            try
            {
                await _hub.Unsubscribe(_observer, cancellationToken);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to unsubscribe live query Orleans bridge during shutdown");
            }
        }

        _observer = null;
        _hub = null;
    }

    private sealed class HubObserver(IAsyncPublisher<DnsQueryEvent> publisher) : ILiveQueryObserver
    {
        public async Task OnEvent(DnsQueryEventMessage evt, CancellationToken cancellationToken = default)
        {
            await publisher.PublishAsync(evt.ToDnsQueryEvent(), cancellationToken);
        }
    }
}
