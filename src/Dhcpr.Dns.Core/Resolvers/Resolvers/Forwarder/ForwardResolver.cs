using System.Collections.Immutable;
using System.Net;

using Dhcpr.Dns.Core.Authoritative;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Forwarder;

/// <summary>
/// Conditional forwarder: longest-suffix match against <see cref="DnsConfiguration.Routes"/>.
/// Unmatched names fall through to recursive resolution.
/// Loaded authoritative zones win over forward routes.
/// </summary>
public sealed class ForwardResolver : IDomainMessageMiddleware, IDisposable
{
    private readonly IInternalDomainClient _internalClient;
    private readonly AuthoritativeZoneStore _authoritativeZones;
    private readonly ILogger<ForwardResolver> _logger;
    private DnsConfiguration _configuration;
    private readonly IDisposable? _subscription;

    public ForwardResolver(
        IOptionsMonitor<DnsConfiguration> options,
        IInternalDomainClient internalClient,
        AuthoritativeZoneStore authoritativeZones,
        ILogger<ForwardResolver> logger)
    {
        _internalClient = internalClient;
        _authoritativeZones = authoritativeZones;
        _logger = logger;
        _configuration = options.CurrentValue;
        _subscription = options.OnChange(c =>
        {
            _configuration = c;
            _logger.LogDebug("Forwarder routes configuration changed");
        });
    }

    public async ValueTask<DomainMessage?> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        if (context.UpstreamEndpoints is { Length: > 0 })
            return null;

        if (context.DomainMessage.Questions.Length == 0)
            return null;

        var questionName = context.DomainMessage.Questions[0].Name;
        if (_authoritativeZones.FindZone(questionName.ToString()) is not null)
            return null;

        var endpoints = MatchRoute(questionName);
        if (endpoints is null || endpoints.Length == 0)
            return null;

        return await _internalClient.SendAsync(
            context,
            context.DomainMessage,
            endpoints.ToImmutableArray(),
            cancellationToken);
    }

    private IPEndPoint[]? MatchRoute(DomainLabels name)
    {
        var routes = _configuration.GetParsedRoutes();
        if (routes.Count == 0)
            return null;

        for (var i = 0; i < name.Labels.Length; i++)
        {
            var suffix = string.Join(".", name.Labels.Skip(i).Select(l => l.Label));
            if (routes.TryGetValue(suffix, out var endpoints))
                return endpoints;
        }

        if (routes.TryGetValue(".", out var defaultEndpoints))
            return defaultEndpoints;

        return null;
    }

    public void Dispose() => _subscription?.Dispose();

    public string Name { get; } = "Forward Resolver";
    public int Priority { get; } = 500;
}
