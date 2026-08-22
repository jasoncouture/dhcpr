using System.Threading.Channels;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Resolvers.Caching;

using Microsoft.Extensions.Hosting;

namespace Dhcpr.Server.Orleans.Cache;

/// <summary>
/// DNS cache mutations enqueue here; a single loop OneWay-sends wire payloads through Orleans.
/// Never awaits observer delivery on the DNS request path.
/// </summary>
public sealed class OrleansDnsCacheEventPublisher : IDnsCacheEventPublisher, IHostedService
{
    private static readonly BoundedChannelOptions _channelOptions = new(16_384)
    {
        FullMode = BoundedChannelFullMode.DropOldest,
        SingleReader = true,
        SingleWriter = false
    };

    private readonly IGrainFactory _grainFactory;
    private readonly Channel<DnsCacheEventMessage> _channel =
        Channel.CreateBounded<DnsCacheEventMessage>(_channelOptions);

    private CancellationTokenSource? _runCancellationTokenSource;
    private Task? _runLoop;

    public OrleansDnsCacheEventPublisher(IGrainFactory grainFactory)
    {
        _grainFactory = grainFactory;
    }

    public Guid OriginId { get; } = Guid.NewGuid();

    public void PublishSet(
        DomainMessage request,
        DomainMessage response,
        DnssecValidationStatus securityStatus,
        DateTimeOffset cachedAt)
        => TryEnqueue(() => DnsCacheEventMessage.Set(OriginId, request, response, securityStatus, cachedAt));

    public void PublishSecurityStatus(DomainMessage request, DnssecValidationStatus securityStatus)
        => TryEnqueue(() => DnsCacheEventMessage.ForSecurityStatus(OriginId, request, securityStatus));

    public void PublishClear()
        => TryEnqueue(() => DnsCacheEventMessage.Clear(OriginId));

    private void TryEnqueue(Func<DnsCacheEventMessage> factory)
    {
        try
        {
            _channel.Writer.TryWrite(factory());
        }
        catch (Exception)
        {
            // Encode/enqueue must not fail the local cache write.
        }
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await Task.Yield();
        _runCancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        _runLoop = RunAsync(_runCancellationTokenSource.Token);
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
        var worker = _grainFactory.GetGrain<IDnsCachePublishWorker>(0);
        var reader = _channel.Reader;
        while (await reader.WaitToReadAsync(cancellationToken))
        {
            while (reader.TryRead(out var evt))
                await worker.PublishAsync(evt, CancellationToken.None);
        }
    }
}
