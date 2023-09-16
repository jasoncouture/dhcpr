using System.Net;

using Dhcpr.Core;
using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Forwarder;

public sealed class ForwardResolver : IDomainMessageMiddleware, IDisposable
{
    private readonly IDisposable? _subscription;
    private readonly IDomainClientFactory _domainClientFactory;
    private readonly ILogger<ForwardResolver> _logger;
    private DnsConfiguration _currentConfiguration;

    public ForwardResolver(
        IOptionsMonitor<DnsConfiguration> options,
        IDomainClientFactory domainClientFactory,
        ILogger<ForwardResolver> logger
    )
    {
        _domainClientFactory = domainClientFactory;
        _logger = logger;
        _currentConfiguration = options.CurrentValue;
        _subscription = options.OnChange(OptionsChanged);
    }

    private void OptionsChanged(DnsConfiguration configuration)
    {
        _currentConfiguration = configuration;
        _logger.LogDebug("Configuration changed applied");
    }

    public void Dispose()
    {
        _subscription?.Dispose();
    }

    public async ValueTask<DomainMessage?> ProcessAsync(DomainMessageContext context, CancellationToken cancellationToken)
    {
        var endPoints = _currentConfiguration.Forwarders.GetForwarderEndpoints();
        if (endPoints.Length == 0) return null;
        
        var clients = await Task.WhenAll(endPoints
            .Select(i => new DomainClientOptions() { EndPoint = i, Type = DomainClientType.Udp })
            .Select(i => _domainClientFactory.GetDomainClient(i, cancellationToken).AsTask()));

        var udpTasks = clients.Select(i =>
            i.SendAsync(context.DomainMessage, cancellationToken).AsTask()
                .ConvertExceptionsToNull())
            .ToPooledList();
        var completed = await Task.WhenAny(udpTasks);

        Task.WhenAll(udpTasks).IgnoreExceptionsAsync().Orphan();
        
        return await completed;
    }

    public string Name { get; } = "Forward Resolver";
    public int Priority { get; } = 500;
}