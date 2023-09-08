using System.Net;

using Dhcpr.Core;
using Dhcpr.Dns.Core.Resolvers.Caching;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Abstractions;

using DNS.Client.RequestResolver;
using DNS.Protocol;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

public sealed class RootResolver : IRootResolver, IDisposable
{
    // ReSharper disable once PrivateFieldCanBeConvertedToLocalVariable
    private readonly IOptionsMonitor<RootServerConfiguration> _rootServerConfigurationOptions;
    private readonly IResolverCache _resolverCache;
    private readonly ILogger<RootResolver> _logger;
    private readonly IMultiResolver _rootResolvers;
    private readonly IDisposable? _subscription;

    private RootServerConfiguration _activeConfiguration = new() { Addresses = Array.Empty<string>() };

    public RootResolver(
        IOptionsMonitor<RootServerConfiguration> rootServerConfigurationOptions,
        IResolverCache resolverCache,
        IServiceProvider serviceProvider,
        ILogger<RootResolver> logger
    )
    {
        _rootServerConfigurationOptions = rootServerConfigurationOptions;
        _resolverCache = resolverCache;
        _logger = logger;
        _rootResolvers = ActivatorUtilities.CreateInstance<RecursiveRootResolver>(serviceProvider,
            GetEndPoints(_rootServerConfigurationOptions.CurrentValue.Addresses));
        _subscription = _rootServerConfigurationOptions.OnChange(ConfigurationChanged);
        ConfigurationChanged(_rootServerConfigurationOptions.CurrentValue, null);
    }

    private static IEnumerable<IPEndPoint> GetEndPoints(IEnumerable<string> endPoints)
    {
        return endPoints.Select(i => i.GetIPEndPoint(53));
    }

    private IEnumerable<IRequestResolver> GetResolvers(IEnumerable<string> endPoints)
    {
        return GetEndPoints(endPoints).Select(i =>
            _resolverCache.GetResolver(i, x => new UdpRequestResolver(x, new TcpRequestResolver(x), 500)));
    }


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

        _logger.LogDebug("Configuration changed applied");
    }

    public async Task<IResponse> Resolve(IRequest request,
        CancellationToken cancellationToken = new CancellationToken())
    {
        return await _rootResolvers.Resolve(request, cancellationToken);
    }

    public void Dispose()
    {
        _subscription?.Dispose();
    }
}