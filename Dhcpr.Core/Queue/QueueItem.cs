namespace Dhcpr.Core.Queue;

public struct QueueItem<T> where T : class
{
    public T Item { get; init; }
    public CancellationToken CancellationToken { get; init; }
}