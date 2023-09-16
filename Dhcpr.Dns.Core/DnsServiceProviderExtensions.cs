using Dhcpr.Core;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Forwarder;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.ObjectPool;

namespace Dhcpr.Dns.Core;

public static class DnsServiceProviderExtensions
{
    public static IServiceCollection AddDns(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddHostedService<DnsServer>();
        services.AddQueueProcessor<DnsPacketReceivedMessage, DomainMessageContextMessageProcessor>(maximumConcurrency: 4096);
        services.AddSingleton<IDomainMessageMiddleware, ForwardResolver>();
        services.AddSingleton<IDomainMessageMiddleware, RecursiveRootResolver>();
        services.AddSingleton<IDomainMessageMiddleware, NameErrorDomainMiddleware>();

        services.AddSingleton<IInternalDomainClient, InternalDomainClient>();
        services.AddSingleton<IDomainClientFactory, DomainClientFactory>();
        
        services.AddSingleton<ISocketFactory, SocketFactory>();

        services.AddSingleton(ObjectPool.Create(new StringBuilderPooledObjectPolicy()));

        services.Configure<DnsConfiguration>(configuration).AddValidation<DnsConfiguration>();
        services.Configure<RootServerConfiguration>(configuration.GetSection(nameof(DnsConfiguration.RootServers)))
            .AddValidation<RootServerConfiguration>();
        return services;
    }
}