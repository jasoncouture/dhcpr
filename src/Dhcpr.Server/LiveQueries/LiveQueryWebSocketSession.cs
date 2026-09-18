using System.Net.WebSockets;
using System.Text.Json;
using System.Threading.Channels;

using Dhcpr.Server.Orleans.LiveQueries;

namespace Dhcpr.Server.LiveQueries;

/// <summary>
/// One WebSocket connection subscribed to <see cref="ILiveQueryHubGrain"/>.
/// DropOldest so a slow client never back-pressures DNS or the hub.
/// </summary>
internal sealed partial class LiveQueryWebSocketSession
{
    internal const int FanOutCapacity = 1000;

    // Backup if a membership notification is missed. Must stay well under ObserverManager expiration.
    private static readonly TimeSpan ResubscribeInterval = TimeSpan.FromSeconds(5);

    private static readonly BoundedChannelOptions ChannelOptions = new(FanOutCapacity)
    {
        FullMode = BoundedChannelFullMode.DropOldest,
        SingleReader = true,
        SingleWriter = false
    };

    public static async Task RunAsync(
        WebSocket socket,
        IGrainFactory grainFactory,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        var channel = Channel.CreateBounded<DnsQueryEventMessage>(ChannelOptions);
        var observerInstance = new HubObserver(channel.Writer);
        var observer = grainFactory.CreateObjectReference<ILiveQueryObserver>(observerInstance);
        var hub = grainFactory.GetGrain<ILiveQueryHubGrain>(Guid.Empty);

        using var runCancellation = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        var runToken = runCancellation.Token;
        try
        {
            var write = WriteLoopAsync(socket, channel.Reader, runToken);
            var receive = ReceiveUntilCloseAsync(socket, runToken);
            var refresh = MaintainSubscriptionAsync(hub, observer, logger, runToken);
            await Task.WhenAny(write, receive, refresh);
            await runCancellation.CancelAsync();
            await Task.WhenAll(
                IgnoreCancelAsync(write),
                IgnoreCancelAsync(receive),
                IgnoreCancelAsync(refresh));
        }
        finally
        {
            channel.Writer.TryComplete();
            try
            {
                await hub.UnsubscribeAsync(observer, CancellationToken.None);
            }
            catch (Exception ex)
            {
                LogUnsubscribeFailed(logger, ex);
            }

            try
            {
                grainFactory.DeleteObjectReference<ILiveQueryObserver>(observer);
            }
            catch (Exception ex)
            {
                LogDeleteObserverFailed(logger, ex);
            }
        }

        if (socket.State is WebSocketState.Open or WebSocketState.CloseReceived)
        {
            await socket.CloseAsync(
                WebSocketCloseStatus.NormalClosure,
                "done",
                CancellationToken.None);
        }
    }

    internal static bool TryEnqueue(ChannelWriter<DnsQueryEventMessage> writer, DnsQueryEventMessage evt)
    {
        if (LiveQueryFilters.IsHealthCheckProbe(evt))
            return false;

        return writer.TryWrite(evt);
    }

    private static async Task WriteLoopAsync(
        WebSocket socket,
        ChannelReader<DnsQueryEventMessage> reader,
        CancellationToken cancellationToken)
    {
        while (await reader.WaitToReadAsync(cancellationToken))
        {
            while (reader.TryRead(out var evt))
            {
                var payload = JsonSerializer.SerializeToUtf8Bytes(
                    LiveQueryWebSocketMessage.From(evt),
                    LiveQueryWebSocketJsonContext.Default.LiveQueryWebSocketMessage);
                await socket.SendAsync(payload, WebSocketMessageType.Text, endOfMessage: true, cancellationToken);
            }
        }
    }

    private static async Task ReceiveUntilCloseAsync(WebSocket socket, CancellationToken cancellationToken)
    {
        var buffer = new byte[1024];
        while (socket.State == WebSocketState.Open)
        {
            var result = await socket.ReceiveAsync(buffer, cancellationToken);
            if (result.MessageType == WebSocketMessageType.Close)
                break;
        }
    }

    private static async Task MaintainSubscriptionAsync(
        ILiveQueryHubGrain hub,
        ILiveQueryObserver observer,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        await TrySubscribeAsync(hub, observer, logger, cancellationToken);
        using var timer = new PeriodicTimer(ResubscribeInterval);
        while (await timer.WaitForNextTickAsync(cancellationToken))
            await TrySubscribeAsync(hub, observer, logger, cancellationToken);
    }

    private static async Task TrySubscribeAsync(
        ILiveQueryHubGrain hub,
        ILiveQueryObserver observer,
        ILogger logger,
        CancellationToken cancellationToken)
    {
        try
        {
            await hub.SubscribeAsync(observer, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            LogRefreshSubscriptionFailed(logger, ex);
        }
    }

    private static async Task IgnoreCancelAsync(Task task)
    {
        try
        {
            await task;
        }
        catch (OperationCanceledException)
        {
        }
        catch (WebSocketException)
        {
        }
        catch (ChannelClosedException)
        {
        }
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "Failed to unsubscribe live query WebSocket during shutdown")]
    private static partial void LogUnsubscribeFailed(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Failed to delete live query WebSocket observer reference")]
    private static partial void LogDeleteObserverFailed(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Failed to refresh live query hub subscription for WebSocket")]
    private static partial void LogRefreshSubscriptionFailed(ILogger logger, Exception exception);

    private sealed class HubObserver : ILiveQueryObserver
    {
        private readonly ChannelWriter<DnsQueryEventMessage> _writer;

        public HubObserver(ChannelWriter<DnsQueryEventMessage> writer)
        {
            _writer = writer;
        }

        public async Task OnEventAsync(DnsQueryEventMessage evt, CancellationToken cancellationToken)
        {
            await Task.Yield();
            TryEnqueue(_writer, evt);
        }
    }
}
