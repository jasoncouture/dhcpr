namespace Dhcpr.Core.Queue;

public interface IMessageQueue<T> where T : class
{
    /// <summary>
    /// Enqueues <paramref name="item"/> together with <paramref name="cancellationToken"/> on the queue entry.
    /// </summary>
    void Enqueue(T item, CancellationToken cancellationToken);

    /// <summary>
    /// Waits for the next queued item.
    /// </summary>
    ValueTask<QueueItem<T>> DequeueAsync(CancellationToken cancellationToken);
}