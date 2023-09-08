using System.Net;

using Dhcpr.Core;

using DNS.Client.RequestResolver;
using DNS.Protocol;
using DNS.Protocol.ResourceRecords;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core;

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