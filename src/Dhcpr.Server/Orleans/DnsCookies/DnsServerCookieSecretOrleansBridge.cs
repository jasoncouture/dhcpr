namespace Dhcpr.Server.Orleans.DnsCookies;

/// <summary>
/// Subscribes to the DNS cookie-secret grain and keeps this silo's
/// snapshot in sync.
/// </summary>
public sealed partial class DnsServerCookieSecretOrleansBridge : IHostedService
{
    private static readonly TimeSpan _resubscribeInterval = TimeSpan.FromSeconds(5);

    private readonly IGrainFactory _grainFactory;
    private readonly IClusterMembershipService _membership;
    private readonly ILogger<DnsServerCookieSecretOrleansBridge> _logger;

    private HubObserver? _observerInstance;
    private IDnsServerCookieSecretObserver? _observer;
    private IDnsServerCookieSecretGrain? _hub;
    private CancellationTokenSource? _resubscribeCancellationTokenSource;
    private Task? _resubscribeLoop;

    public DnsServerCookieSecretOrleansBridge(
        IGrainFactory grainFactory,
        IClusterMembershipService membership,
        ILogger<DnsServerCookieSecretOrleansBridge> logger)
    {
        _grainFactory = grainFactory;
        _membership = membership;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await Task.Yield();
        _observerInstance = new HubObserver();
        _observer = _grainFactory.CreateObjectReference<IDnsServerCookieSecretObserver>(_observerInstance);
        _hub = _grainFactory.GetGrain<IDnsServerCookieSecretGrain>(DnsServerCookieSecretGrain.Key);

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
                _grainFactory.DeleteObjectReference<IDnsServerCookieSecretObserver>(_observer);
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
            await _hub!.SubscribeAsync(_observer!, DnsServerCookieSecretSnapshot.Get(), cancellationToken);
            if (DnsServerCookieSecretSnapshot.Get() is not { Length: >= 16 })
                DnsServerCookieSecretSnapshot.Replace(await _hub.GetOrCreateAsync());
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

    [LoggerMessage(Level = LogLevel.Debug, Message = "Failed to unsubscribe DNS cookie-secret Orleans bridge during shutdown")]
    private static partial void LogUnsubscribeFailed(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Failed to delete DNS cookie-secret observer reference during shutdown")]
    private static partial void LogDeleteObserverFailed(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Failed to refresh DNS cookie-secret grain subscription")]
    private static partial void LogRefreshSubscriptionFailed(ILogger logger, Exception exception);

    private sealed class HubObserver : IDnsServerCookieSecretObserver
    {
        public async Task OnSecretAsync(byte[] secret, CancellationToken cancellationToken)
        {
            await Task.Yield();
            DnsServerCookieSecretSnapshot.Replace(secret);
        }
    }
}
