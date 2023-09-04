using Dhcpr.Core.Queue;

using Microsoft.Extensions.DependencyInjection;

namespace Dhcpr.Core;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddCoreServices(this IServiceCollection services)
    {
        services.AddSingleton(typeof(IMessageQueue<>), typeof(MessageQueue<>));

        return services;
    }
}