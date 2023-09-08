using Dhcpr.Core;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Dhcpr.Dhcp.Core;

public sealed class DhcpConfiguration : IValidateSelf
{
    // TODO
    public bool Validate()
    {
        throw new NotImplementedException();
    }
}

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddDhcp(this IServiceCollection services, IConfiguration configuration)
    {
        // TODO: Add DHCP components and configuration.
        return services;
    }
}