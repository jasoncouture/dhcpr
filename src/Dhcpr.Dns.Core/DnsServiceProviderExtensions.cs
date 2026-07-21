using Dhcpr.Core;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Resolvers.Caching;
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
        services.AddMemoryCache(o =>
        {
            o.SizeLimit = 100_000;
            o.CompactionPercentage = 0.25;
            o.ExpirationScanFrequency = TimeSpan.FromMinutes(1);
        });
        services.AddSingleton<IDnsResponseCache, DnsResponseCache>();

        services.AddHostedService<DnsServer>();
        services.AddQueueProcessor<DnsPacketReceivedMessage, DomainMessageContextMessageProcessor>(maximumConcurrency: 4096);
        services.AddSingleton<IDomainMessageMiddleware, ForwardResolver>();
        services.AddSingleton<IDomainMessageMiddleware, RecursiveRootResolver>();
        services.AddSingleton<IDomainMessageMiddleware, NameErrorDomainMiddleware>();
        // Outermost last: Logging → Cache → CanonicalName → resolver
        services.Decorate<IDomainMessageMiddleware, CanonicalNameResolverDecorator>();
        services.Decorate<IDomainMessageMiddleware, CacheResolverDecorator>();
        services.Decorate<IDomainMessageMiddleware, QueryLoggingDomainMessageMiddleware>();
        // Registered after Decorate so this is not wrapped by cache/CNAME/logging decorators.
        services.AddSingleton<IDomainMessageMiddleware, MetricsDomainMessageMiddleware>();

        services.AddSingleton<IInternalDomainClient, InternalDomainClient>();
        services.AddSingleton<IDomainClientFactory, DomainClientFactory>();

        services.AddSingleton<ISocketFactory, SocketFactory>();

        services.AddSingleton(ObjectPool.Create(new StringBuilderPooledObjectPolicy()));

        services.AddOptions<DnsConfiguration>()
            .Bind(configuration)
            .Validate(o => o.Validate(), "Invalid DNS configuration")
            .ValidateOnStart();
        services.AddOptions<RootServerConfiguration>()
            .Bind(configuration.GetSection(nameof(DnsConfiguration.RootServers)))
            .Validate(o => o.Validate(), "Invalid DNS root server configuration")
            .ValidateOnStart();
        return services;
    }
}