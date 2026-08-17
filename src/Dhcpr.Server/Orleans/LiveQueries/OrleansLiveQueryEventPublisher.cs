using System.Threading.Channels;

using Dhcpr.Dns.Core.Protocol.Processing;

using Microsoft.Extensions.Hosting;

namespace Dhcpr.Server.Orleans.LiveQueries;

/// <summary>
/// DNS publishes into a DropOldest channel; a single loop OneWay-sends to Orleans.
/// Never awaits grain calls on the DNS request path.
/// </summary>
public sealed class OrleansLiveQueryEventPublisher : ILiveQueryEventPublisher, IHostedService
{
    private static readonly BoundedChannelOptions _channelOptions = new(4096)
    {
        FullMode = BoundedChannelFullMode.DropOldest,
        SingleReader = true,
        SingleWriter = false
    };

    private readonly IGrainFactory _grainFactory;
    private readonly Channel<DnsQueryEventMessage> _channel =
        Channel.CreateBounded<DnsQueryEventMessage>(_channelOptions);

    private CancellationTokenSource? _runCancellationTokenSource;
    private Task? _runLoop;

    public OrleansLiveQueryEventPublisher(IGrainFactory grainFactory)
    {
        _grainFactory = grainFactory;
    }

    public ValueTask PublishAsync(DnsQueryEvent evt, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        _channel.Writer.TryWrite(DnsQueryEventMessage.From(evt));
        return ValueTask.CompletedTask;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        _runCancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _runLoop = RunAsync(_runCancellationTokenSource.Token);
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        _channel.Writer.TryComplete();

        if (_runCancellationTokenSource is not null)
        {
            await _runCancellationTokenSource.CancelAsync();
            _runCancellationTokenSource.Dispose();
            _runCancellationTokenSource = null;
        }

        if (_runLoop is not null)
        {
            try
            {
                await _runLoop.WaitAsync(cancellationToken);
            }
            catch (OperationCanceledException)
            {
                // Ignored — shutdown.
            }
            catch (ChannelClosedException)
            {
                // Ignored — writer completed.
            }

            _runLoop = null;
        }
    }

    private async Task RunAsync(CancellationToken cancellationToken)
    {
        var worker = _grainFactory.GetGrain<ILiveQueryPublishWorker>(0);
        var reader = _channel.Reader;
        while (await reader.WaitToReadAsync(cancellationToken))
        {
            while (reader.TryRead(out var evt))
            {
                // OneWay: await only until local enqueue into the worker mailbox.
                await worker.PublishAsync(evt, CancellationToken.None);
            }
        }
    }
}
