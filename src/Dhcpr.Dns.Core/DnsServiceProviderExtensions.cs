using Dhcpr.Core;
using Dhcpr.Dns.Core.Authoritative;
using Dhcpr.Dns.Core.ConfiguredRecords;
using Dhcpr.Dns.Core.DynamicDns;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Resolvers.Caching;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Forwarder;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;
using Dhcpr.Dns.Core.RootZone;
using Dhcpr.Dns.Core.Validation;

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
        // Process-bound: shared response cache across all queries.
        services.TryAddSingleton<IDnsCacheEventPublisher, NoOpDnsCacheEventPublisher>();
        services.AddSingleton<IDnsResponseCache, DnsResponseCache>();

        services.AddHttpClient(nameof(NamedRootHttpClient), ConfigureInternicHttpClient);
        services.AddHttpClient(nameof(RootZoneHttpClient), ConfigureInternicHttpClient);
        services.AddScoped<INamedRootHttpClient, NamedRootHttpClient>();
        services.AddScoped<IRootZoneHttpClient, RootZoneHttpClient>();
        // Process-bound mutable state.
        services.AddSingleton<IRootServerTips, RootServerTips>();
        services.AddSingleton<IRootZoneStore, RootZoneStore>();
        services.AddSingleton<IAuthoritativeZoneStore, AuthoritativeZoneStore>();
        services.AddSingleton<IDynamicDnsStore, DynamicDnsStore>();
        // Tips bootstrap before root.zone refresh (registration order = start order).
        services.AddHostedService<RootServerTipsBootstrapService>();
        services.AddHostedService<RootZoneRefreshService>();
        services.AddHostedService<AuthoritativeZoneLoader>();
        services.AddHostedService<DynamicDnsLoader>();
        // Process-bound: OnChange → shared cache.Clear().
        services.AddHostedService<DnsConfigurationCacheInvalidator>();

        services.AddSingleton<IDnsListenerReadiness, DnsListenerReadiness>();
        services.AddHostedService<DnsServer>();
        services.AddQueueProcessor<DnsPacketReceivedMessage, DomainMessageContextMessageProcessor>(maximumConcurrency: 4096);
        services.AddScoped<RootZoneMiddleware>();
        services.AddScoped<UpstreamQueryMiddleware>();
        services.AddScoped<ConfiguredRecordMiddleware>();
        services.AddScoped<DynamicDnsMiddleware>();
        services.AddScoped<AuthoritativeZoneMiddleware>();
        services.AddScoped<AuthoritativeNsCutMiddleware>();
        services.AddScoped<ForwardResolver>();
        services.AddScoped<RecursiveRootResolver>();
        services.AddScoped<ServerFailureDomainMiddleware>();
        services.AddScoped<IDomainMessageMiddleware>(static sp => new CompositeDomainMessageMiddleware(
            sp.GetRequiredService<RootZoneMiddleware>(),
            sp.GetRequiredService<UpstreamQueryMiddleware>(),
            sp.GetRequiredService<ConfiguredRecordMiddleware>(),
            sp.GetRequiredService<DynamicDnsMiddleware>(),
            sp.GetRequiredService<AuthoritativeZoneMiddleware>(),
            sp.GetRequiredService<AuthoritativeNsCutMiddleware>(),
            sp.GetRequiredService<ForwardResolver>(),
            sp.GetRequiredService<RecursiveRootResolver>(),
            sp.GetRequiredService<ServerFailureDomainMiddleware>()));
        // Outermost last: Logging → Metrics → Shuffle → DNSSEC → …
        // Inside cache, inside ServFailRetry: sibling A/AAAA warm only on miss.
        services.Decorate<IDomainMessageMiddleware, AddressPrefetchMiddleware>();
        services.Decorate<IDomainMessageMiddleware, ServFailRetryDecorator>();
        // Inside cache: sinkhole NXDOMAIN is stored so regex/suffix match runs once.
        services.Decorate<IDomainMessageMiddleware, BlackholeDomainMiddleware>();
        // Inside cache: BIND CHAOS bait is stored. ip.info is DoNotCacheResponse.
        services.Decorate<IDomainMessageMiddleware, BindChaosMiddleware>();
        // Inside cache: NOTIMP / REFUSED policy answers live for an hour.
        services.Decorate<IDomainMessageMiddleware, UnsupportedQueryTypeMiddleware>();
        // Inside cache: RFC 6303 empty reverse NXDOMAIN, no public leak/SERVFAIL.
        services.Decorate<IDomainMessageMiddleware, Rfc6303EmptyZoneMiddleware>();
        // Inside cache: RFC 9462 resolver.arpa is local and stored (never forwarded).
        services.Decorate<IDomainMessageMiddleware, ResolverArpaMiddleware>();
        services.Decorate<IDomainMessageMiddleware, CacheResolverDecorator>();
        services.Decorate<IDomainMessageMiddleware, CanonicalNameResolverDecorator>();
        // Outside CNAME so chased assemblies still get RA (previously stamped before chase).
        services.Decorate<IDomainMessageMiddleware, RecursionAvailableMiddleware>();
        services.Decorate<IDomainMessageMiddleware, DnssecValidationMiddleware>();
        // Outside cache so HIT responses still rotate A/AAAA order per client query.
        services.Decorate<IDomainMessageMiddleware, AnswerShuffleMiddleware>();
        // Outside Blackhole/Unsupported so sinkhole + NOTIMP still increment dns.queries.
        services.Decorate<IDomainMessageMiddleware, MetricsDomainMessageMiddleware>();
        // Outermost logging so Unsupported/Blackhole answers are still recorded.
        services.Decorate<IDomainMessageMiddleware, QueryLoggingDomainMessageMiddleware>();

        // Process-bound: MessagePipe live-query dispatch (Orleans replaces this).
        services.TryAddSingleton<ILiveQueryEventPublisher, NoOpLiveQueryEventPublisher>();
        services.AddSingleton<IUdpQueryRateLimiter, SlidingWindowUdpQueryRateLimiter>();
        services.TryAddSingleton<IDnsServerCookieSecretSource, ProcessLocalDnsServerCookieSecretSource>();
        services.AddSingleton<IDnsServerCookieFactory, DnsServerCookieFactory>();

        services.AddScoped<IReferralWalker, ReferralWalker>();
        services.AddScoped<IInternalDomainClient, InternalDomainClient>();
        services.AddScoped<IDnsQueryExecutor, DnsQueryExecutor>();
        services.AddSingleton<IDnsMetrics, DnsMetricsPublisher>();
        services.AddScoped<IDomainClientFactory, DomainClientFactory>();
        services.AddScoped<IEdnsProtocolService, EdnsProtocolService>();
        services.AddScoped<IDnssecValidator, DnssecValidator>();
        services.TryAddSingleton(TimeProvider.System);
        services.AddScoped<IDnssecMessageValidator, DnssecMessageValidator>();
        services.AddScoped<ISocketFactory, SocketFactory>();
        // Process-bound: shared StringBuilder pool.
        services.AddSingleton(ObjectPool.Create(new StringBuilderPooledObjectPolicy()));
        // Process-bound: in-memory cert + mtime (Kestrel / DnsServer read it).
        services.AddSingleton<ITlsServerCertificateProvider, FileTlsServerCertificateProvider>();
        // Process-bound: options validation is resolved from the root provider.
        services.AddSingleton<IValidateOptions<DnsConfiguration>, DnsConfigurationValidator>();
        services.AddSingleton<IValidateOptions<TlsConfiguration>, TlsConfigurationValidator>();
        services.AddOptionsWithValidateOnStart<DnsConfiguration>()
            .BindConfiguration("DNS");
        services.AddOptionsWithValidateOnStart<TlsConfiguration>()
            .BindConfiguration("TLS");
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
