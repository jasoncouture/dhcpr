using Dhcpr.Core;
using Dhcpr.Dns.Core.Resolvers;

using DNS.Client.RequestResolver;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

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
        
        services.Configure<DnsConfiguration>(configuration).AddValidation<DnsConfiguration>();
        services.Configure<RootServerConfiguration>(configuration.GetSection(nameof(DnsConfiguration.RootServers))).AddValidation<RootServerConfiguration>();
        return services;
    }
}