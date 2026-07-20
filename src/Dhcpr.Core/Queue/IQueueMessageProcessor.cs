using System.Diagnostics.CodeAnalysis;

namespace Dhcpr.Core.Queue;

[SuppressMessage("ReSharper", "TypeParameterCanBeVariant")]
public interface IQueueMessageProcessor<T> where T : class
{
    Task ProcessMessageAsync(T message, CancellationToken cancellationToken);
}