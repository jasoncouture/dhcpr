namespace Dhcpr.Core.Queue;

public sealed class QueueProcessorConfiguration
{
    public int MaximumConcurrency { get; set; } = 1;
}