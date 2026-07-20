using Dhcpr.Core.Queue;

using Microsoft.Extensions.DependencyInjection;

namespace Dhcpr.Core;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddQueueProcessor<TMessage, TService>(
        this IServiceCollection services,
        int maximumConcurrency = -1,
        ServiceLifetime lifetime = ServiceLifetime.Scoped
    )
        where TService : IQueueMessageProcessor<TMessage>
        where TMessage : class
    {
        if (maximumConcurrency == -1)
            maximumConcurrency = Environment.ProcessorCount;
        else if (maximumConcurrency <= 0)
            throw new ArgumentOutOfRangeException(nameof(maximumConcurrency));
        var configurationName = typeof(TMessage).FullName ??
                                throw new InvalidOperationException("Unable to get type name for requested message type");
        // In configure, we set the concurrency to the maximum value we've seen thus far
        services.Configure<QueueProcessorConfiguration>(configurationName, i =>
        {
            if (maximumConcurrency > i.MaximumConcurrency)
                i.MaximumConcurrency = maximumConcurrency;
        });

        // And in post configure, we pull it back down to the minimum
        services.PostConfigure<QueueProcessorConfiguration>(configurationName, i =>
        {
            if (i.MaximumConcurrency > maximumConcurrency)
                i.MaximumConcurrency = maximumConcurrency;
        });

        services.Add(ServiceDescriptor.Describe(typeof(IQueueMessageProcessor<TMessage>), typeof(TService), lifetime));
        services.AddHostedService<QueueProcessorService<TMessage>>(s => ActivatorUtilities.CreateInstance<QueueProcessorService<TMessage>>(s, configurationName));
        return services;
    }

    public static IServiceCollection AddCoreServices(this IServiceCollection services)
    {
        services.AddSingleton(typeof(IMessageQueue<>), typeof(MessageQueue<>));
        services.AddHostedService<HeartBeatPublisherService>();
        return services;
    }
}