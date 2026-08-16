namespace Dhcpr.Core.Queue;

public interface IMessageQueue<T> where T : class
{
    void Enqueue(T item, CancellationToken cancellationToken);

    ValueTask<QueueItem<T>> DequeueAsync(CancellationToken cancellationToken);
}