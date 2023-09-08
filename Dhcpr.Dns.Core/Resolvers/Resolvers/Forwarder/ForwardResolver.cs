using System.Net;

using Dhcpr.Dns.Core.Resolvers.Caching;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Abstractions;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Wrappers;

using DNS.Client.RequestResolver;
using DNS.Protocol;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Forwarder;

public class ForwardResolver : MultiResolver, IForwardResolver, IDisposable
{
    private readonly IDisposable? _subscription;
    private readonly IOptionsMonitor<DnsConfiguration> _options;
    private readonly IResolverCache _resolverCache;
    private readonly ILogger<ForwardResolver> _logger;
    private DnsConfiguration _currentConfiguration;

    public ForwardResolver(IOptionsMonitor<DnsConfiguration> options, IResolverCache resolverCache, ILogger<ForwardResolver> logger)
    {
        _options = options;
        _resolverCache = resolverCache;
        _logger = logger;
        _currentConfiguration = options.CurrentValue;
        _subscription = options.OnChange(OptionsChanged);
    }

    private void OptionsChanged(DnsConfiguration configuration, string? name)
    {
        _currentConfiguration = configuration;
        _logger.LogDebug("Configuration changed applied");
    }

    private IRequestResolver GetForwardResolvers()
    {
        return _resolverCache.GetResolver(
            _currentConfiguration.GetForwarderEndpoints(),
            CreateMultiResolver,
            CreateInnerResolver
        );
    }

    private UdpRequestResolver CreateInnerResolver(IPEndPoint resolvers)
    {
        return new UdpRequestResolver(resolvers, new TcpRequestResolver(resolvers));
    }

    private ParallelResolver CreateMultiResolver(IEnumerable<IRequestResolver> resolvers)
    {
        return new ParallelResolver(resolvers);
    }

    public override async Task<IResponse?> Resolve(IRequest request,
        CancellationToken cancellationToken = new())
    {
        var forwardResolver = GetForwardResolvers();
        return await forwardResolver.Resolve(request, cancellationToken).ConfigureAwait(false);
    }

    public void Dispose()
    {
        _subscription?.Dispose();
        GC.SuppressFinalize(this);
    }
}