namespace Dhcpr.Server.Orleans.DataProtection;

/// <summary>
/// Subscribes to the Data Protection grain and keeps this silo's
/// snapshot in sync.
/// </summary>
public sealed partial class DataProtectionKeyOrleansBridge : IHostedService
{
    private static readonly TimeSpan _resubscribeInterval = TimeSpan.FromSeconds(5);

    private readonly IGrainFactory _grainFactory;
    private readonly IClusterMembershipService _membership;
    private readonly ILogger<DataProtectionKeyOrleansBridge> _logger;

    private HubObserver? _observerInstance;
    private IDataProtectionKeyObserver? _observer;
    private IDataProtectionKeyGrain? _hub;
    private CancellationTokenSource? _resubscribeCancellationTokenSource;
    private Task? _resubscribeLoop;

    public DataProtectionKeyOrleansBridge(
        IGrainFactory grainFactory,
        IClusterMembershipService membership,
        ILogger<DataProtectionKeyOrleansBridge> logger)
    {
        _grainFactory = grainFactory;
        _membership = membership;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await Task.Yield();
        _observerInstance = new HubObserver();
        _observer = _grainFactory.CreateObjectReference<IDataProtectionKeyObserver>(_observerInstance);
        _hub = _grainFactory.GetGrain<IDataProtectionKeyGrain>(DataProtectionKeyGrain.Key);

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
                LogUnsubscribeFailed(_logger, ex);
            }

            try
            {
                _grainFactory.DeleteObjectReference<IDataProtectionKeyObserver>(_observer);
            }
            catch (Exception ex)
            {
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
            await TrySubscribeAsync(cancellationToken);
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
            await _hub!.SubscribeAsync(_observer!, DataProtectionKeySnapshot.Copy(), cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            LogRefreshSubscriptionFailed(_logger, ex);
        }
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "Failed to unsubscribe Data Protection Orleans bridge during shutdown")]
    private static partial void LogUnsubscribeFailed(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Failed to delete Data Protection observer reference during shutdown")]
    private static partial void LogDeleteObserverFailed(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Failed to refresh Data Protection grain subscription")]
    private static partial void LogRefreshSubscriptionFailed(ILogger logger, Exception exception);

    private sealed class HubObserver : IDataProtectionKeyObserver
    {
        public async Task OnKeysAsync(IEnumerable<string> elementXml, CancellationToken cancellationToken)
        {
            await Task.Yield();
            DataProtectionKeySnapshot.Replace(elementXml);
        }
    }
}
