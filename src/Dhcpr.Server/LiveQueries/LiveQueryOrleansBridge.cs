using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Server.Orleans.LiveQueries;

using MessagePipe;

using Microsoft.Extensions.Hosting;

namespace Dhcpr.Server.LiveQueries;

public sealed partial class LiveQueryOrleansBridge : IHostedService
{
    // Shorter than hub ObserverManager expiration so this silo's subscription is not dropped.
    private static readonly TimeSpan ResubscribeInterval = TimeSpan.FromMinutes(2);

    private readonly IGrainFactory _grainFactory;
    private readonly IAsyncPublisher<DnsQueryEvent> _publisher;
    private readonly ILogger<LiveQueryOrleansBridge> _logger;

    // Orleans CreateObjectReference keeps only a WeakReference to the target — must root it.
    private HubObserver? _observerInstance;
    private ILiveQueryObserver? _observer;
    private ILiveQueryHubGrain? _hub;
    private CancellationTokenSource? _resubscribeCancellation;
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

        _resubscribeCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _resubscribeLoop = ResubscribeLoopAsync(_resubscribeCancellation.Token);
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (_resubscribeCancellation is not null)
        {
            await _resubscribeCancellation.CancelAsync();
            _resubscribeCancellation.Dispose();
            _resubscribeCancellation = null;
        }

        if (_resubscribeLoop is not null)
        {
            try
            {
                await _resubscribeLoop;
            }
            catch (OperationCanceledException)
            {
                // Ignored — expected when shutdown cancels the refresh loop.
            }

            _resubscribeLoop = null;
        }

        if (_hub is not null && _observer is not null)
        {
            try
            {
                await _hub.Unsubscribe(_observer, cancellationToken);
            }
            catch (OperationCanceledException)
            {
                // Ignored — expected when shutdown cancels an in-flight unsubscribe.
            }
            catch (Exception ex)
            {
                // Best-effort cleanup: failing unsubscribe must not block host stop.
                LogUnsubscribeFailed(_logger, ex);
            }

            try
            {
                _grainFactory.DeleteObjectReference<ILiveQueryObserver>(_observer);
            }
            catch (Exception ex)
            {
                // Best-effort cleanup: failing DeleteObjectReference must not block host stop.
                LogDeleteObserverFailed(_logger, ex);
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
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                // Boundary: one failed refresh must not kill the loop / host.
                LogRefreshSubscriptionFailed(_logger, ex);
            }
        }
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "Failed to unsubscribe live query Orleans bridge during shutdown")]
    private static partial void LogUnsubscribeFailed(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Failed to delete live query observer reference during shutdown")]
    private static partial void LogDeleteObserverFailed(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Failed to refresh live query hub subscription")]
    private static partial void LogRefreshSubscriptionFailed(ILogger logger, Exception exception);

    private sealed class HubObserver : ILiveQueryObserver
    {
        private readonly IAsyncPublisher<DnsQueryEvent> _publisher;

        public HubObserver(IAsyncPublisher<DnsQueryEvent> publisher)
        {
            _publisher = publisher;
        }

        public Task OnEvent(DnsQueryEventMessage evt, CancellationToken cancellationToken)
        {
            // Sync Publish: OneWay observer must not block the Orleans callback path.
            _publisher.Publish(evt.ToDnsQueryEvent(), cancellationToken);
            return Task.CompletedTask;
        }
    }
}
