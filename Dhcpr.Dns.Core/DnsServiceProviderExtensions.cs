using Dhcpr.Core;
using Dhcpr.Dns.Core.Resolvers;
using Dhcpr.Dns.Core.Resolvers.Caching;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Abstractions;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Forwarder;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Wrappers;

using DNS.Client.RequestResolver;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.ObjectPool;

namespace Dhcpr.Dns.Core;

public static class DnsServiceProviderExtensions
{
    public static IServiceCollection AddDns(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddHostedService<DnsServerHostedService>();
        
        services.AddSingleton<IDnsResolver, DnsResolver>();
        services.AddSingleton<IParallelDnsResolver, ParallelResolver>();
        services.AddSingleton<ISequentialDnsResolver, SequentialDnsResolver>();
        services.AddSingleton<IRequestResolver, InternalResolver>();
        services.AddSingleton<IRootResolver, RootResolver>();
        services.AddSingleton<IResolverCache, ResolverCache>();
        services.AddSingleton<IDnsCache, DnsCache>();
        services.AddSingleton<IForwardResolver, ForwardResolver>();

        services.AddSingleton(ObjectPool.Create(new StringBuilderPooledObjectPolicy()));
        
        services.Configure<DnsConfiguration>(configuration).AddValidation<DnsConfiguration>();
        services.Configure<RootServerConfiguration>(configuration.GetSection(nameof(DnsConfiguration.RootServers))).AddValidation<RootServerConfiguration>();
        return services;
    }
}