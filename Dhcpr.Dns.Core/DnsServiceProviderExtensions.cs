using Dhcpr.Core;
using Dhcpr.Dns.Core.Resolvers;
using Dhcpr.Dns.Core.Resolvers.Caching;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Abstractions;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Database;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Forwarder;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;
using Dhcpr.Dns.Core.Resolvers.Resolvers.SystemResolver;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Wrappers;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Internal;
using Microsoft.Extensions.ObjectPool;

namespace Dhcpr.Dns.Core;

public static class DnsServiceProviderExtensions
{
    public static IServiceCollection AddDns(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddHostedService<DnsServerHostedService>();
        services.AddHostedService<DatabaseCacheItemLoader>();

        services.AddSingleton<IDnsMemoryCacheWriter, DnsMemoryCacheWriter>();
        services.AddSingleton<IDnsOutputFilter, DnsOutputFilter>();
        
        services.AddQueueProcessor<DnsCacheMessage, DnsCacheMessageProcessor>();
        
        
        services.AddScoped<ISystemNameResolver, SystemNameResolver>();
        

        services.AddSingleton(typeof(IScopedResolverWrapper<>), typeof(ScopedResolverWrapper<>));
        services.AddScoped<IDatabaseResolver, DatabaseResolver>();
        services.AddScoped<IDnsResolver, DnsResolver>();
        services.AddSingleton<ISequentialDnsResolver, SequentialDnsResolver>();
        services.AddSingleton<IRootResolver, RootResolver>();
        services.AddSingleton<IResolverCache, ResolverCache>();
        services.AddSingleton<IDnsCache, DnsCache>();
        services.Decorate<IDnsResolver, CachedDnsResolver>();
        services.AddSingleton<IForwardResolver, ForwardResolver>();

        services.AddSingleton(ObjectPool.Create(new StringBuilderPooledObjectPolicy()));

        services.Configure<DnsConfiguration>(configuration).AddValidation<DnsConfiguration>();
        services.Configure<RootServerConfiguration>(configuration.GetSection(nameof(DnsConfiguration.RootServers)))
            .AddValidation<RootServerConfiguration>();
        return services;
    }
}