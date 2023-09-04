using System.Collections.Concurrent;
using System.Diagnostics.CodeAnalysis;

namespace Dhcpr.Core.Queue;

[SuppressMessage("ReSharper", "StaticMemberInGenericType")]
public class MessageQueue<T> : IMessageQueue<T> where T : class
{
    private TaskCompletionSource _queueWaitTask = new();

    public MessageQueue()
    {
        _queueWaitTask.TrySetResult();
    }

    private readonly ConcurrentQueue<QueueItem<T>> _queue = new();

    public void Enqueue(T item, CancellationToken cancellationToken = default)
    {
        _queue.Enqueue(new QueueItem<T> { Item = item, CancellationToken = cancellationToken });
        UpdateSignalState();
    }

    private async ValueTask WaitForSignalAsync(CancellationToken cancellationToken)
    {
        if (_queueWaitTask.Task.IsCompleted)
            return;
        while (true)
        {
            try
            {
                UpdateSignalState();
                var waitTask = _queueWaitTask.Task;
                await waitTask.WaitAsync(Constants.GetPollWaitTimeoutWithJitter(), cancellationToken);

                return;
            }
            catch (TimeoutException) when (!cancellationToken.IsCancellationRequested)
            {
                // Ignored.
            }
            catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
            {
                // Ignored, we timed out.
            }
        }
    }

    private void UpdateSignalState()
    {
        if (_queue.IsEmpty)
        {
            SignalQueueNotReady();
            return;
        }

        SignalQueueReady();
    }

    private void SignalQueueReady()
    {
        SetSignal(true);
    }

    private void SignalQueueNotReady()
    {
        SetSignal(false);
    }

    private void SetSignal(bool signaled)
    {
        var waitSource = _queueWaitTask;
        if (_queueWaitTask.Task.IsCompleted == signaled && waitSource.Task.IsCompleted == signaled) return;

        lock (waitSource)
        {
            if (signaled)
            {
                waitSource.TrySetResult();
            }

            var newSource = new TaskCompletionSource();

            lock (newSource)
            {
                // Make sure no one else can change the new source either.
                if (waitSource == Interlocked.CompareExchange
                    (
                        ref _queueWaitTask,
                        newSource,
                        waitSource
                    ))
                {
                    waitSource.TrySetResult();
                }
            }
        }
    }

    public bool TryDequeue(out QueueItem<T> item) => _queue.TryDequeue(out item);
    public bool IsEmpty => _queue.IsEmpty;

    public async ValueTask<QueueItem<T>> DequeueAsync(CancellationToken cancellationToken = default)
    {
        QueueItem<T> item;
        while (!_queue.TryDequeue(out item))
        {
            UpdateSignalState();
            await WaitForSignalAsync(cancellationToken);
        }

        return item;
    }
}