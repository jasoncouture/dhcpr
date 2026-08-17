using System.Diagnostics.CodeAnalysis;

namespace Dhcpr.Core.Queue;

[SuppressMessage("ReSharper", "TypeParameterCanBeVariant")]
public interface IQueueMessageProcessor<T> where T : class
{
    /// <summary>
    /// Processes a dequeued <paramref name="message"/>.
    /// </summary>
    Task ProcessMessageAsync(T message, CancellationToken cancellationToken);
}