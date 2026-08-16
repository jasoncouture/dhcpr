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
    /// <summary>
    /// Must be shorter than hub <c>ObserverManager</c> expiration so this silo's
    /// subscription is not dropped.
    /// </summary>
    private static readonly TimeSpan ResubscribeInterval = TimeSpan.FromMinutes(2);

    private readonly IGrainFactory _grainFactory;
    private readonly IAsyncPublisher<DnsQueryEvent> _publisher;
    private readonly ILogger<LiveQueryOrleansBridge> _logger;

    // Orleans CreateObjectReference keeps only a WeakReference to the target — must root it.
    private HubObserver? _observerInstance;
    private ILiveQueryObserver? _observer;
    private ILiveQueryHubGrain? _hub;
    private CancellationTokenSource? _resubscribeCts;
    private Task? _resubscribeLoop;

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

        _resubscribeCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _resubscribeLoop = ResubscribeLoopAsync(_resubscribeCts.Token);
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (_resubscribeCts is not null)
        {
            await _resubscribeCts.CancelAsync();
            _resubscribeCts.Dispose();
            _resubscribeCts = null;
        }

        if (_resubscribeLoop is not null)
        {
            try
            {
                await _resubscribeLoop;
            }
            catch (OperationCanceledException)
            {
            }

            _resubscribeLoop = null;
        }

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

    private async Task ResubscribeLoopAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(ResubscribeInterval);
        while (await timer.WaitForNextTickAsync(cancellationToken))
        {
            try
            {
                await _hub!.Subscribe(_observer!, cancellationToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogWarning(ex, "Failed to refresh live query hub subscription");
            }
        }
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
