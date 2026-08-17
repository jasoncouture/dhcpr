using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Server.Orleans.LiveQueries;

using MessagePipe;

using Microsoft.Extensions.Hosting;

using Orleans.Runtime;

namespace Dhcpr.Server.LiveQueries;

public sealed partial class LiveQueryOrleansBridge : IHostedService
{
    // Backup if a membership notification is missed. Must stay well under ObserverManager expiration.
    private static readonly TimeSpan _resubscribeInterval = TimeSpan.FromSeconds(5);

    private readonly IGrainFactory _grainFactory;
    private readonly IAsyncPublisher<DnsQueryEvent> _publisher;
    private readonly IClusterMembershipService _membership;
    private readonly ILogger<LiveQueryOrleansBridge> _logger;

    // Orleans CreateObjectReference keeps only a WeakReference to the target — must root it.
    private HubObserver? _observerInstance;
    private ILiveQueryObserver? _observer;
    private ILiveQueryHubGrain? _hub;
    private CancellationTokenSource? _resubscribeCancellationTokenSource;
    private Task? _resubscribeLoop;

    public LiveQueryOrleansBridge(
        IGrainFactory grainFactory,
        IAsyncPublisher<DnsQueryEvent> publisher,
        IClusterMembershipService membership,
        ILogger<LiveQueryOrleansBridge> logger)
    {
        _grainFactory = grainFactory;
        _publisher = publisher;
        _membership = membership;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await Task.Yield();
        _observerInstance = new HubObserver(_publisher);
        _observer = _grainFactory.CreateObjectReference<ILiveQueryObserver>(_observerInstance);
        _hub = _grainFactory.GetGrain<ILiveQueryHubGrain>(Guid.Empty);

        // Do not await the first Subscribe here: after a rolling deploy the hub may still
        // be registered on a dying silo, and a blocking grain call stalls Kestrel/DNS startup.
        _resubscribeCancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _resubscribeLoop = MaintainSubscriptionAsync(_resubscribeCancellationTokenSource.Token);
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (_resubscribeCancellationTokenSource is not null)
        {
            await _resubscribeCancellationTokenSource.CancelAsync();
            _resubscribeCancellationTokenSource.Dispose();
            _resubscribeCancellationTokenSource = null;
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
                await _hub.UnsubscribeAsync(_observer, cancellationToken);
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

    private async Task MaintainSubscriptionAsync(CancellationToken cancellationToken)
    {
        await TrySubscribeAsync(cancellationToken);

        var membershipWatch = WatchMembershipAsync(cancellationToken);
        var periodic = PeriodicSubscribeAsync(cancellationToken);
        await Task.WhenAll(membershipWatch, periodic);
    }

    private async Task WatchMembershipAsync(CancellationToken cancellationToken)
    {
        await foreach (var _ in _membership.MembershipUpdates.WithCancellation(cancellationToken))
        {
            // Hub grain reactivates empty when its silo dies; re-attach this observer immediately.
            await TrySubscribeAsync(cancellationToken);
        }
    }

    private async Task PeriodicSubscribeAsync(CancellationToken cancellationToken)
    {
        using var timer = new PeriodicTimer(_resubscribeInterval);
        while (await timer.WaitForNextTickAsync(cancellationToken))
            await TrySubscribeAsync(cancellationToken);
    }

    private async Task TrySubscribeAsync(CancellationToken cancellationToken)
    {
        try
        {
            await _hub!.SubscribeAsync(_observer!, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Boundary: one failed refresh must not kill the loop / host.
            LogRefreshSubscriptionFailed(_logger, ex);
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

        public async Task OnEventAsync(DnsQueryEventMessage evt, CancellationToken cancellationToken)
        {
            await Task.Yield();
            // Sync Publish: OneWay observer must not block the Orleans callback path.
            _publisher.Publish(evt.ToDnsQueryEvent(), cancellationToken);
        }
    }
}
