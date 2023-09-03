using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Dhcpr.Dhcp.Core;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddDhcp(this IServiceCollection services, IConfiguration configuration)
    {
        // TODO: Add DHCP components and configuration.

        services.Configure<DhcpConfiguration>(configuration);
        services.AddHostedService<DhcpServerHostedService>();
        return services;
    }
}