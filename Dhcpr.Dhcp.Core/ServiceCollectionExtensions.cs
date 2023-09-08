using System.Collections.Immutable;
using System.Net;

using Dhcpr.Core;
using Dhcpr.Dhcp.Core.Client;
using Dhcpr.Dhcp.Core.Pipeline;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Dhcpr.Dhcp.Core;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddDhcp(this IServiceCollection services, IConfiguration configuration)
    {
        // TODO: Add DHCP components and configuration.

        services.Configure<DhcpConfiguration>(configuration);
        var testNetwork = new IPNetwork(IPAddress.Parse("10.0.0.1"), IPAddress.Parse("255.255.255.0"),
            IPAddress.Parse("10.0.0.255"));
        // Temporary for testing
        services.AddSingleton<IDhcpSubnet>(_ => new DhcpSubnet(testNetwork,
            new[] { new IPAddressRange(IPAddress.Parse("10.0.0.100"), IPAddress.Parse("10.0.0.200")) }
                .ToImmutableArray()));

        services.AddSingleton<IDhcpLeasePool, DhcpLeasePool>();


        services.AddSingleton<IDhcpRequestHandler, DhcpLoggingRequestHandler>();
        services.AddSingleton<IDhcpRequestHandler, DhcpNetworkValidationRequestHandler>();
        services.AddSingleton<IDhcpRequestHandler, DhcpMessageTypeValidatorRequestHandler>();
        services.AddSingleton<IDhcpRequestHandler, DhcpDiscoverRequestHandler>();
        services.AddSingleton<IDhcpRequestHandler, DhcpSelectRequestHandler>();

        services.AddHostedService<DhcpServerHostedService>();
        services.AddQueueProcessor<QueuedDhcpMessage, DhcpMessageQueueProcessor>();
        return services;
    }
}