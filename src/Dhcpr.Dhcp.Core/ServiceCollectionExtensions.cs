using System.Collections.Immutable;
using System.Net;

using Dhcpr.Core;
using Dhcpr.Dhcp.Core.Client;
using Dhcpr.Dhcp.Core.Pipeline;

using Microsoft.Extensions.DependencyInjection;

namespace Dhcpr.Dhcp.Core;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddDhcp(this IServiceCollection services)
    {
        // TODO: Add DHCP components and configuration.

        services.AddOptionsWithValidateOnStart<DhcpConfiguration>()
            .BindConfiguration("Dhcp");
        var testNetwork = new DhcpNetwork(IPAddress.Parse("10.0.0.1"), IPAddress.Parse("255.255.255.0"),
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

        services.AddSingleton<IDhcpMetrics, DhcpMetricsPublisher>();
        services.AddHostedService<DhcpServerHostedService>();
        services.AddQueueProcessor<QueuedDhcpMessage, DhcpMessageQueueProcessor>();
        return services;
    }
}
