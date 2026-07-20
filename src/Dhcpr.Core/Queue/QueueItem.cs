namespace Dhcpr.Core.Queue;

public sealed record class QueueItem<T>(
    T Item,
    CancellationToken CancellationToken
) where T : class;