using System.Collections.Concurrent;

using Dhcpr.Core.Linq;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Dhcpr.Core.Queue;

public sealed class QueueProcessorService<T> : BackgroundService where T : class
{
    private readonly IMessageQueue<T> _messageQueue;
    private readonly IServiceProvider _serviceProvider;
    private readonly QueueProcessorConfiguration _options;
    private readonly ConcurrentQueue<CancellationTokenSource> _cancellationTokenSourceQueue = new();
    private IQueueMessageProcessor<T>[]? _processors;

    public QueueProcessorService(string configurationName, IOptionsFactory<QueueProcessorConfiguration> optionsFactory,
        IMessageQueue<T> messageQueue, IServiceProvider serviceProvider)
    {
        ArgumentException.ThrowIfNullOrEmpty(configurationName);
        _messageQueue = messageQueue;
        _serviceProvider = serviceProvider;
        _options = optionsFactory.Create(configurationName);
    }

    private (CancellationTokenSource cancellationTokenSource, CancellationTokenRegistration subscription)
        GetCancellationTokenSource(
            CancellationToken cancellationToken,
            CancellationToken stoppingToken
        )
    {
        _cancellationTokenSourceQueue.TryDequeue(out var cancellationTokenSource);
        cancellationTokenSource ??= CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        var subscription = cancellationToken.Register(static o => (o as CancellationTokenSource)?.Cancel(),
            cancellationTokenSource);
        return (cancellationTokenSource, subscription);
    }

    private async ValueTask ReturnCancellationTokenSource(
        (CancellationTokenSource cancellationTokenSource, CancellationTokenRegistration subscription) tokenSourceTuple)
    {
        var (cancellationTokenSource, subscription) = tokenSourceTuple;
        await subscription.DisposeAsync();
        if (cancellationTokenSource.TryReset())
            _cancellationTokenSourceQueue.Enqueue(cancellationTokenSource);
    }

    private async Task ProcessNextMessageAsync(T message, CancellationToken cancellationToken,
        CancellationToken stoppingToken)
    {
        var rentedCancellationTokenSource = GetCancellationTokenSource(cancellationToken, stoppingToken);
        try
        {
            var token = rentedCancellationTokenSource.cancellationTokenSource.Token;
            var processors = _processors ??= _serviceProvider.GetServices<IQueueMessageProcessor<T>>().ToArray();
            await RunMessageProcessorsAsync(message, processors, token);
        }
        finally
        {
            await ReturnCancellationTokenSource(rentedCancellationTokenSource);
        }
    }

    private static async Task RunMessageProcessorsAsync(T message,
        IReadOnlyList<IQueueMessageProcessor<T>> messageProcessors,
        CancellationToken token
    )
    {
        using var disposable = message as IDisposable;
        if (messageProcessors.Count == 1)
        {
            await messageProcessors[0].ProcessMessageAsync(message, token);
            return;
        }

        await Task.WhenAll(messageProcessors.Select(i => i.ProcessMessageAsync(message, token)));
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Resolve once — processors are singletons for the DNS hot path.
        _processors = _serviceProvider.GetServices<IQueueMessageProcessor<T>>().ToArray();

        var tasks = ListPool<Task>.Default.Get();
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    while (tasks.Count >= _options.MaximumConcurrency && tasks.Count > 0)
                    {
                        if (await RemoveCompletedTasks(tasks))
                            continue;
                        await Task.WhenAny(tasks);
                    }

                    var (message, cancellationToken) =
                        await _messageQueue.DequeueAsync(stoppingToken);
                    tasks.Add(ProcessNextMessageAsync(message, cancellationToken, stoppingToken));
                }
                catch (OperationCanceledException) when (
                    !stoppingToken.IsCancellationRequested
                )
                {
                    /* Ignored */
                }
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            if (tasks.Count > 0)
            {
                try
                {
                    await Task.WhenAll(tasks);
                }
                catch
                {
                    // Ignored, we're shutting down, exceptions are expected.
                }
            }
        }
    }

    private static async Task<bool> RemoveCompletedTasks(IList<Task> tasks)
    {
        using var completedTasks = tasks.Where(i => i.IsCompleted)
            .Select((i, index) => new { Task = i, Index = index })
            .OrderByDescending(i => i.Index)
            .ToPooledList();

        bool any = false;
        foreach (var item in completedTasks)
        {
            any = true;
            tasks.RemoveAt(item.Index);
            await item.Task;
        }

        return any;
    }
}
