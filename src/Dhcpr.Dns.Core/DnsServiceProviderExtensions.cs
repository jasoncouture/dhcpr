using Dhcpr.Core;
using Dhcpr.Dns.Core.Authoritative;
using Dhcpr.Dns.Core.DynamicDns;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Resolvers.Caching;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Forwarder;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;
using Dhcpr.Dns.Core.RootZone;
using Dhcpr.Dns.Core.Validation;

using MessagePipe;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.ObjectPool;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core;

public static class DnsServiceProviderExtensions
{
    public static IServiceCollection AddDns(this IServiceCollection services)
    {
        services.AddMemoryCache(o =>
        {
            // Size is per DnsResponseCache entry (Size = 1). 100M was effectively unbounded
            // and could grow until the pod OOMs after sustained query load.
            o.SizeLimit = 100_000;
            o.CompactionPercentage = 0.25;
            o.ExpirationScanFrequency = TimeSpan.FromMinutes(1);
        });
        services.AddMessagePipe();
        services.AddSingleton<IDnsResponseCache, DnsResponseCache>();

        services.AddHttpClient<INamedRootHttpClient, NamedRootHttpClient>(ConfigureInternicHttpClient);
        services.AddHttpClient<IRootZoneHttpClient, RootZoneHttpClient>(ConfigureInternicHttpClient);
        services.AddSingleton<IRootServerTips, RootServerTips>();
        services.AddSingleton<IRootZoneStore, RootZoneStore>();
        services.AddSingleton<IAuthoritativeZoneStore, AuthoritativeZoneStore>();
        services.AddSingleton<DynamicDnsStore>();
        // Tips bootstrap before root.zone refresh (registration order = start order).
        services.AddHostedService<RootServerTipsBootstrapService>();
        services.AddHostedService<RootZoneRefreshService>();
        services.AddHostedService<AuthoritativeZoneLoader>();
        services.AddHostedService<DynamicDnsLoader>();

        services.AddHostedService<DnsServer>();
        services.AddQueueProcessor<DnsPacketReceivedMessage, DomainMessageContextMessageProcessor>(maximumConcurrency: 4096);
        services.AddSingleton<IDomainMessageMiddleware, RootZoneMiddleware>();
        services.AddSingleton<IDomainMessageMiddleware, UpstreamQueryMiddleware>();
        services.AddSingleton<IDomainMessageMiddleware, DynamicDnsMiddleware>();
        services.AddSingleton<IDomainMessageMiddleware, AuthoritativeZoneMiddleware>();
        services.AddSingleton<IDomainMessageMiddleware, AuthoritativeNsCutMiddleware>();
        services.AddSingleton<IDomainMessageMiddleware, ForwardResolver>();
        services.AddSingleton<IDomainMessageMiddleware, RecursiveRootResolver>();
        services.AddSingleton<IDomainMessageMiddleware, ServerFailureDomainMiddleware>();
        // Outermost last: Logging → Metrics → Blackhole → Unsupported → Shuffle → Dnssec → …
        services.Decorate<IDomainMessageMiddleware, ServFailRetryDecorator>();
        services.Decorate<IDomainMessageMiddleware, CacheResolverDecorator>();
        services.Decorate<IDomainMessageMiddleware, CanonicalNameResolverDecorator>();
        // Outside CNAME so chased assemblies still get RA (previously stamped before chase).
        services.Decorate<IDomainMessageMiddleware, RecursionAvailableMiddleware>();
        services.Decorate<IDomainMessageMiddleware, DnssecValidationMiddleware>();
        // Outside cache so HIT responses still rotate A/AAAA order per client query.
        services.Decorate<IDomainMessageMiddleware, AnswerShuffleMiddleware>();
        // Unknown QTYPE (e.g. ANY/255) → NOTIMP before cache/upstream.
        services.Decorate<IDomainMessageMiddleware, UnsupportedQueryTypeMiddleware>();
        // Blackhole suffixes → NXDOMAIN (still outside cache/upstream).
        services.Decorate<IDomainMessageMiddleware, BlackholeDomainMiddleware>();
        // Outside Blackhole/Unsupported so sinkhole + NOTIMP still increment dns.queries.
        services.Decorate<IDomainMessageMiddleware, MetricsDomainMessageMiddleware>();
        // Outermost logging so Unsupported/Blackhole answers are still recorded.
        services.Decorate<IDomainMessageMiddleware, QueryLoggingDomainMessageMiddleware>();

        // Live UI publishes from DomainMessageContextMessageProcessor (once per external answer).
        services.TryAddSingleton<ILiveQueryEventPublisher, NoOpLiveQueryEventPublisher>();

        services.AddSingleton<IReferralWalker, ReferralWalker>();
        services.AddSingleton<IInternalDomainClient, InternalDomainClient>();
        services.AddSingleton<IDnsQueryExecutor, DnsQueryExecutor>();
        services.AddSingleton<IDomainClientFactory, DomainClientFactory>();
        services.AddSingleton<IEdnsProtocolService, EdnsProtocolService>();
        services.AddSingleton<IDnssecValidator, DnssecValidator>();
        services.AddSingleton<DnssecMessageValidator>();

        services.AddSingleton<ISocketFactory, SocketFactory>();

        services.AddSingleton(ObjectPool.Create(new StringBuilderPooledObjectPolicy()));

        services.AddSingleton<IValidateOptions<DnsConfiguration>, DnsConfigurationValidator>();
        services.AddOptionsWithValidateOnStart<DnsConfiguration>()
            .BindConfiguration("DNS");
        services.AddOptionsWithValidateOnStart<RootServerConfiguration>()
            .BindConfiguration("DNS:RootServers")
            .Validate(static o => o.Validate(), "Invalid DNS root server configuration");
        services.AddOptionsWithValidateOnStart<DynamicDnsConfiguration>()
            .BindConfiguration("DynamicDns")
            .Validate(static o => o.Validate(out _), "Invalid DynamicDns configuration");
        return services;
    }

    private static void ConfigureInternicHttpClient(HttpClient client)
    {
        // InterNIC returns 403 without a User-Agent.
        client.Timeout = TimeSpan.FromMinutes(5);
        client.DefaultRequestHeaders.UserAgent.ParseAdd("dhcpr/1.0");
    }
}
