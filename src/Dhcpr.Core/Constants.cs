namespace Dhcpr.Core;

static class Constants
{
    public static TimeSpan QueuePoolTimeout { get; } = TimeSpan.FromSeconds(0.2);
    public const int QueueWaitTimeoutJitterMilliseconds = 100;

    public static TimeSpan GetPollWaitTimeoutWithJitter()
    {
        return QueuePoolTimeout.Add
        (
            TimeSpan.FromMilliseconds(Random.Shared.Next(0, QueueWaitTimeoutJitterMilliseconds))
        );
    }
}