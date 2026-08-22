using Dhcpr.Dns.Core.Resolvers.Caching;
using Dhcpr.Server.Orleans.Cache;

using Microsoft.Extensions.Hosting;

using Orleans.Runtime;

namespace Dhcpr.Server.Cache;

/// <summary>
/// Subscribes to cluster cache events and imports the wire payload into the local cache.
/// </summary>
public sealed partial class DnsCacheOrleansBridge : IHostedService
{
    private static readonly TimeSpan _resubscribeInterval = TimeSpan.FromSeconds(5);

    private readonly IGrainFactory _grainFactory;
    private readonly IDnsResponseCache _cache;
    private readonly IDnsCacheEventPublisher _publisher;
    private readonly IClusterMembershipService _membership;
    private readonly ILogger<DnsCacheOrleansBridge> _logger;

    private HubObserver? _observerInstance;
    private IDnsCacheObserver? _observer;
    private IDnsCacheHubGrain? _hub;
    private CancellationTokenSource? _resubscribeCancellationTokenSource;
    private Task? _resubscribeLoop;

    public DnsCacheOrleansBridge(
        IGrainFactory grainFactory,
        IDnsResponseCache cache,
        IDnsCacheEventPublisher publisher,
        IClusterMembershipService membership,
        ILogger<DnsCacheOrleansBridge> logger)
    {
        _grainFactory = grainFactory;
        _cache = cache;
        _publisher = publisher;
        _membership = membership;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await Task.Yield();
        _observerInstance = new HubObserver(_cache, _publisher.OriginId, _logger);
        _observer = _grainFactory.CreateObjectReference<IDnsCacheObserver>(_observerInstance);
        _hub = _grainFactory.GetGrain<IDnsCacheHubGrain>(DnsCacheHubGrain.Key);

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
                _grainFactory.DeleteObjectReference<IDnsCacheObserver>(_observer);
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
            await _hub!.SubscribeAsync(_observer!, cancellationToken);
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

    [LoggerMessage(Level = LogLevel.Debug, Message = "Failed to unsubscribe DNS cache Orleans bridge during shutdown")]
    private static partial void LogUnsubscribeFailed(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Failed to delete DNS cache observer reference during shutdown")]
    private static partial void LogDeleteObserverFailed(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Failed to refresh DNS cache hub subscription")]
    private static partial void LogRefreshSubscriptionFailed(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Ignoring malformed DNS cache replica event")]
    private static partial void LogMalformedEvent(ILogger logger, Exception exception);

    private sealed class HubObserver : IDnsCacheObserver
    {
        private readonly IDnsResponseCache _cache;
        private readonly Guid _originId;
        private readonly ILogger _logger;

        public HubObserver(IDnsResponseCache cache, Guid originId, ILogger logger)
        {
            _cache = cache;
            _originId = originId;
            _logger = logger;
        }

        public async Task OnEventAsync(DnsCacheEventMessage evt, CancellationToken cancellationToken)
        {
            await Task.Yield();
            if (evt.OriginId == _originId)
                return;

            try
            {
                Apply(evt);
            }
            catch (Exception ex)
            {
                LogMalformedEvent(_logger, ex);
            }
        }

        private void Apply(DnsCacheEventMessage evt)
        {
            switch (evt.Kind)
            {
                case DnsCacheEventKind.Set:
                    if (evt.TryGetRequest(out var request) && evt.TryGetResponse(out var response))
                        _cache.Import(request, response, evt.GetSecurityStatus(), evt.CachedAt);
                    break;
                case DnsCacheEventKind.UpdateSecurityStatus:
                    if (evt.TryGetRequest(out var statusRequest))
                        _cache.ImportSecurityStatus(statusRequest, evt.GetSecurityStatus());
                    break;
                case DnsCacheEventKind.Clear:
                    _cache.ImportClear();
                    break;
            }
        }
    }
}
