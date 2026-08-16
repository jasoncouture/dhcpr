using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Server.Orleans.LiveQueries;

using MessagePipe;

using Microsoft.Extensions.Hosting;

using Orleans.Concurrency;

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

    // Orleans CreateObjectReference keeps only a WeakReference to the target — must root it.
    private HubObserver? _observerInstance;
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
        _observerInstance = new HubObserver(_publisher);
        _observer = _grainFactory.CreateObjectReference<ILiveQueryObserver>(_observerInstance);
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

            try
            {
                _grainFactory.DeleteObjectReference<ILiveQueryObserver>(_observer);
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed to delete live query observer reference during shutdown");
            }
        }

        _observer = null;
        _observerInstance = null;
        _hub = null;
    }

    private sealed class HubObserver(IAsyncPublisher<DnsQueryEvent> publisher) : ILiveQueryObserver
    {
        public Task OnEvent(DnsQueryEventMessage evt, CancellationToken cancellationToken)
        {
            // Sync Publish: OneWay observer must not block the Orleans callback path.
            publisher.Publish(evt.ToDnsQueryEvent(), cancellationToken);
            return Task.CompletedTask;
        }
    }
}
