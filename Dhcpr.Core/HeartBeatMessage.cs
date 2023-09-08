namespace Dhcpr.Core;

public sealed record HeartBeatMessage(TimeSpan ElapsedSinceLastMessage, DateTimeOffset Sent,
    DateTimeOffset FirstHeartbeatTime) : IDisposable
{
    private readonly TaskCompletionSource _taskCompletionSource = new TaskCompletionSource();
    internal bool Complete { get; private set; } = false;
    internal Task Task => _taskCompletionSource.Task;

    void IDisposable.Dispose()
    {
        Complete = true;
        _taskCompletionSource.TrySetResult();
    }
}