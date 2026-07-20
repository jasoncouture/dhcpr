namespace Dhcpr.Core.Queue;

public sealed class QueueProcessorConfiguration
{
    public int MaximumConcurrency { get; set; } = 1;

    /// <summary>
    /// When false, processors are resolved once from the root provider (Singleton lifetime).
    /// When true, each message gets a DI scope (Scoped lifetime).
    /// </summary>
    public bool ScopePerMessage { get; set; } = true;
}