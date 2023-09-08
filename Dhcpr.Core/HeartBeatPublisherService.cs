using Dhcpr.Core.Queue;

using Microsoft.Extensions.Hosting;

namespace Dhcpr.Core;

public sealed class HeartBeatPublisherService : BackgroundService
{
    private readonly IMessageQueue<HeartBeatMessage> _heartBeatQueue;

    public HeartBeatPublisherService(IMessageQueue<HeartBeatMessage> heartBeatQueue)
    {
        _heartBeatQueue = heartBeatQueue;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var periodicTimer = new PeriodicTimer(TimeSpan.FromSeconds(1));
        DateTimeOffset start = DateTimeOffset.Now;
        DateTimeOffset lastMessageSent = DateTimeOffset.Now;
        try
        {
            while (await periodicTimer.WaitForNextTickAsync(stoppingToken).ConfigureAwait(false))
            {
                var now = DateTimeOffset.Now;
                var message = new HeartBeatMessage(now - lastMessageSent, now, start);
                lastMessageSent = DateTimeOffset.Now;
                _heartBeatQueue.Enqueue(message, stoppingToken);
                // Wait for the message to complete processing.
                await message.Task.WaitAsync(stoppingToken).ConfigureAwait(false);
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Ignored.
        }
    }
}