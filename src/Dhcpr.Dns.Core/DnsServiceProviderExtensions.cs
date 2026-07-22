using Dhcpr.Core;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Resolvers.Caching;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Forwarder;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.ObjectPool;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core;

public static class DnsServiceProviderExtensions
{
    public static IServiceCollection AddDns(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddMemoryCache(o =>
        {
            o.SizeLimit = 100_000_000;
            o.CompactionPercentage = 0.25;
            o.ExpirationScanFrequency = TimeSpan.FromMinutes(1);
        });
        services.AddSingleton<IDnsResponseCache, DnsResponseCache>();

        services.AddHostedService<DnsServer>();
        services.AddQueueProcessor<DnsPacketReceivedMessage, DomainMessageContextMessageProcessor>(maximumConcurrency: 4096);
        services.AddSingleton<IDomainMessageMiddleware, UpstreamQueryMiddleware>();
        services.AddSingleton<IDomainMessageMiddleware, ForwardResolver>();
        services.AddSingleton<IDomainMessageMiddleware, RecursiveRootResolver>();
        services.AddSingleton<IDomainMessageMiddleware, NameErrorDomainMiddleware>();
        // Outermost last: Logging → Cache → CanonicalName → resolver
        services.Decorate<IDomainMessageMiddleware, CanonicalNameResolverDecorator>();
        services.Decorate<IDomainMessageMiddleware, CacheResolverDecorator>();
        services.Decorate<IDomainMessageMiddleware, QueryLoggingDomainMessageMiddleware>();
        // Registered after Decorate so this is not wrapped by cache/CNAME/logging decorators.
        services.Decorate<IDomainMessageMiddleware, MetricsDomainMessageMiddleware>();

        services.AddSingleton<IInternalDomainClient, InternalDomainClient>();
        services.AddSingleton<IDomainClientFactory, DomainClientFactory>();

        services.AddSingleton<ISocketFactory, SocketFactory>();

        services.AddSingleton(ObjectPool.Create(new StringBuilderPooledObjectPolicy()));

        services.AddSingleton<IValidateOptions<DnsConfiguration>, DnsConfigurationValidator>();
        services.AddOptionsWithValidateOnStart<DnsConfiguration>()
            .Bind(configuration.GetSection("DNS"));
        services.AddOptionsWithValidateOnStart<RootServerConfiguration>()
            .Bind(configuration.GetSection("DNS:RootServers"))
            .Validate(static o => o.Validate(), "Invalid DNS root server configuration");
        return services;
    }
}

file sealed class DnsConfigurationValidator : IValidateOptions<DnsConfiguration>
{
    public ValidateOptionsResult Validate(string? name, DnsConfiguration options)
        => options.TryValidate(out var error)
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(error!);
}
