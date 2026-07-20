namespace Dhcpr.Core.Queue;

public interface IMessageQueue<T> where T : class
{
    void Enqueue(T item, CancellationToken cancellationToken = default);

    ValueTask<QueueItem<T>> DequeueAsync(CancellationToken cancellationToken = default);
}