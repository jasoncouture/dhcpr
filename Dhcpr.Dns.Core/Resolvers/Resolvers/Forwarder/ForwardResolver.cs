using System.Net;

using Dhcpr.Dns.Core.Resolvers.Caching;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Abstractions;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Wrappers;

using DNS.Client.RequestResolver;
using DNS.Protocol;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Forwarder;

public sealed class ForwardResolver : MultiResolver, IForwardResolver, IDisposable
{
    private readonly IDisposable? _subscription;
    private readonly IResolverCache _resolverCache;
    private readonly ILogger<ForwardResolver> _logger;
    private DnsConfiguration _currentConfiguration;

    public ForwardResolver(IOptionsMonitor<DnsConfiguration> options, IResolverCache resolverCache,
        ILogger<ForwardResolver> logger)
    {
        _resolverCache = resolverCache;
        _logger = logger;
        _currentConfiguration = options.CurrentValue;
        _subscription = options.OnChange(OptionsChanged);
    }

    private void OptionsChanged(DnsConfiguration configuration)
    {
        _currentConfiguration = configuration;
        _logger.LogDebug("Configuration changed applied");
    }

    private IRequestResolver GetForwardResolvers()
    {
        if (_currentConfiguration.Forwarders.Parallel)
            return _resolverCache.GetResolver(
                _currentConfiguration.Forwarders.GetForwarderEndpoints(),
                CreateParallelMultiResolver,
                CreateInnerResolver
            );
        
        return _resolverCache.GetResolver(
            _currentConfiguration.Forwarders.GetForwarderEndpoints(),
            CreateSequentialMultiResolver,
            CreateInnerResolver
        );
    }

    private UdpRequestResolver CreateInnerResolver(IPEndPoint resolvers)
    {
        return new UdpRequestResolver(resolvers, new TcpRequestResolver(resolvers), timeout: 500);
    }

    private ParallelResolver CreateParallelMultiResolver(IEnumerable<IRequestResolver> resolvers)
    {
        return new ParallelResolver(resolvers);
    }
    
    private SequentialDnsResolver CreateSequentialMultiResolver(IEnumerable<IRequestResolver> resolvers)
    {
        return new SequentialDnsResolver(resolvers);
    }

    public override async Task<IResponse?> Resolve(IRequest request,
        CancellationToken cancellationToken = new())
    {
        var forwardResolver = GetForwardResolvers();
        return await forwardResolver.Resolve(request, cancellationToken);
    }

    public void Dispose()
    {
        _subscription?.Dispose();
        GC.SuppressFinalize(this);
    }
}