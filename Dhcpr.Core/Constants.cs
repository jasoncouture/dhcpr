namespace Dhcpr.Core;

static class Constants
{
    public static readonly TimeSpan QueuePoolTimeout = TimeSpan.FromSeconds(0.2);
    public static readonly int QueueWaitTimeoutJitterMilliseconds = 100;

    public static TimeSpan GetPollWaitTimeoutWithJitter()
    {
        return QueuePoolTimeout.Add
        (
            TimeSpan.FromMilliseconds(Random.Shared.Next(0, QueueWaitTimeoutJitterMilliseconds))
        );
    }
}