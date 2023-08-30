using System.Net;

using Dhcpr.Core;

using DNS.Client.RequestResolver;
using DNS.Protocol;
using DNS.Protocol.ResourceRecords;

using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core;

public record struct MultiResolverCacheKey(ResolverCacheKey[] InnerCacheKeys, Type ResolverType);

public record struct ResolverCacheKey(IPEndPoint EndPoint, Type ResolverType)
{
    public static ResolverCacheKey Create<T>(IPEndPoint endPoint) where T : IRequestResolver
    {
        return new ResolverCacheKey(endPoint, typeof(T));
    }
}

public interface IResolverCache
{
    T GetResolver<T>(IPEndPoint endPoint, Func<IPEndPoint, T> createResolverCallback) where T : IRequestResolver;

    public TOuter GetMultiResolver<TOuter, TInner>
    (
        IEnumerable<IPEndPoint> endPoints,
        Func<IEnumerable<IRequestResolver>, TOuter> createMultiResolver,
        Func<IPEndPoint, TInner> createInnerResolver
    )
        where TOuter : MultiResolver
        where TInner : IRequestResolver;
}

public sealed class ResolverCache : IResolverCache
{
    private readonly IMemoryCache _memoryCache;
    private readonly ILogger<ResolverCache> _logger;

    public ResolverCache(IMemoryCache memoryCache, ILogger<ResolverCache> logger)
    {
        _memoryCache = memoryCache;
        _logger = logger;
    }

    public T GetResolver<T>(IPEndPoint endPoint, Func<IPEndPoint, T> createResolverCallback) where T : IRequestResolver
    {
        var key = ResolverCacheKey.Create<T>(endPoint);
        if (_memoryCache.TryGetValue<T>(key, out var resolver) && resolver is not null)
            return resolver;
        resolver = createResolverCallback.Invoke(endPoint);

        using var cacheEntry = _memoryCache.CreateEntry(key);
        cacheEntry.Value = resolver;
        cacheEntry.SetAbsoluteExpiration(DateTimeOffset.Now.AddHours(24));
        cacheEntry.SetSlidingExpiration(TimeSpan.FromMinutes(5));
        cacheEntry.Priority = CacheItemPriority.Low;
        cacheEntry.Dispose();
        _logger.LogInformation("Cache miss for resolver key: {key}, resolver {type}:{hashCode} created", key,
            resolver.GetType(), resolver.GetHashCode());
        return resolver;
    }

    public TOuter GetMultiResolver<TOuter, TInner>(IEnumerable<IPEndPoint> endPoints,
        Func<IEnumerable<IRequestResolver>, TOuter> createMultiResolver, Func<IPEndPoint, TInner> createInnerResolver)
        where TOuter : MultiResolver
        where TInner : IRequestResolver
    {
        using var orderedEndPoints = endPoints.OrderBy(i => i.ToString()).ToPooledList();
        var cacheKey =
            new MultiResolverCacheKey(
                orderedEndPoints.Select(i => new ResolverCacheKey(i, typeof(TInner))).ToArray(), typeof(TOuter));
        if (_memoryCache.TryGetValue<TOuter>(cacheKey, out var cachedResolver) && cachedResolver is not null)
            return cachedResolver;
        using var innerResolvers = orderedEndPoints.Select(i => GetResolver(i, createInnerResolver))
            .ToPooledList();
        cachedResolver = createMultiResolver.Invoke(innerResolvers.Cast<IRequestResolver>());
        using var cacheEntry = _memoryCache.CreateEntry(cacheKey);
        cacheEntry.Value = cachedResolver;
        cacheEntry.SetAbsoluteExpiration(DateTimeOffset.Now.AddHours(24));
        cacheEntry.SetSlidingExpiration(TimeSpan.FromMinutes(5));
        cacheEntry.Priority = CacheItemPriority.Low;
        cacheEntry.Dispose();

        return cachedResolver;
    }
}

public class RootResolver : IRootResolver, IDisposable
{
    // ReSharper disable once PrivateFieldCanBeConvertedToLocalVariable
    private readonly IOptionsMonitor<RootServerConfiguration> _rootServerConfigurationOptions;
    private readonly IResolverCache _resolverCache;
    private readonly IServiceProvider _serviceProvider;
    private readonly IMultiResolver _rootResolvers;
    private readonly IDisposable? _subscription;

    private RootServerConfiguration _activeConfiguration = new() { Addresses = Array.Empty<string>() };

    public RootResolver(
        IOptionsMonitor<RootServerConfiguration> rootServerConfigurationOptions,
        IResolverCache resolverCache,
        IServiceProvider serviceProvider
    )
    {
        _rootServerConfigurationOptions = rootServerConfigurationOptions;
        _resolverCache = resolverCache;
        _serviceProvider = serviceProvider;
        _rootResolvers = ActivatorUtilities.CreateInstance<RecursiveResolver>(serviceProvider,
            GetEndPoints(_rootServerConfigurationOptions.CurrentValue.Addresses));
        _subscription = _rootServerConfigurationOptions.OnChange(ConfigurationChanged);
        ConfigurationChanged(_rootServerConfigurationOptions.CurrentValue, null);
    }

    private static IEnumerable<IPEndPoint> GetEndPoints(IEnumerable<string> endPoints)
    {
        return endPoints.Select(i => i.GetEndpoint(53));
    }

    private IEnumerable<IRequestResolver> GetResolvers(IEnumerable<string> endPoints)
    {
        return GetEndPoints(endPoints).Select(i => _resolverCache.GetResolver(i, x => new UdpRequestResolver(x)));
    }


    private IRequestResolver GetCachedResolver(IPEndPoint endPoint)
        => _resolverCache.GetResolver<UdpRequestResolver>(endPoint, CreateResolverCallback);

    private UdpRequestResolver CreateResolverCallback(IPEndPoint endPoint)
        => new UdpRequestResolver(endPoint);

    private void ConfigurationChanged(RootServerConfiguration configuration, string? _)
    {
        lock (_rootResolvers)
        {
            if (_activeConfiguration.Addresses.OrderBy(i => i).SequenceEqual(configuration.Addresses.OrderBy(i => i)))
            {
                return;
            }

            _rootResolvers.ReplaceResolvers(GetResolvers(configuration.Addresses)
                .ToArray());
            _activeConfiguration = configuration;
        }
    }

    public async Task<IResponse> Resolve(IRequest request,
        CancellationToken cancellationToken = new CancellationToken())
    {
        return await _rootResolvers.Resolve(request, cancellationToken).ConfigureAwait(false);
    }

    public void Dispose()
    {
        _subscription?.Dispose();
    }
}