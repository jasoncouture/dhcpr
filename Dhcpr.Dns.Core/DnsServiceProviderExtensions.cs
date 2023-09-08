using Dhcpr.Core;

using DNS.Client.RequestResolver;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Dhcpr.Dns.Core;

public static class DnsServiceProviderExtensions
{
    public static IServiceCollection AddDns(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddHostedService<DnsServerHostedService>();
        services.Configure<DnsConfiguration>(configuration).AddValidation<DnsConfiguration>();
        services.AddSingleton<IDnsResolver, DnsResolver>();
        services.AddSingleton<IParallelDnsResolver, ParallelResolver>();
        services.AddSingleton<ISequentialDnsResolver, SequentialDnsResolver>();
        services.AddSingleton<IRequestResolver, InternalResolver>();
        services.Configure<DnsConfiguration>(configuration).AddValidation<DnsConfiguration>();
        return services;
    }
}