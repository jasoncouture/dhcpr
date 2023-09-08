namespace Dhcpr.Core.Queue;

public interface IMessageQueue<T> where T : class
{
    void Enqueue(T item, CancellationToken cancellationToken = default);
    bool TryDequeue(out QueueItem<T> item);
    bool IsEmpty { get; }

    ValueTask<QueueItem<T>> DequeueAsync(CancellationToken cancellationToken = default);
}