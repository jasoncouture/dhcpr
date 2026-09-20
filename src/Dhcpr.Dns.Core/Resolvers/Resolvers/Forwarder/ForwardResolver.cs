using System.Collections.Immutable;
using System.Net;

using Dhcpr.Dns.Core.Authoritative;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Forwarder;

/// <summary>
/// Conditional forwarder: longest-suffix match against <see cref="DnsConfiguration.Routes"/>.
/// Unmatched names fall through to recursive resolution.
/// Loaded authoritative zones win over forward routes.
/// Decorator around recurse. Directed hops skip.
/// </summary>
public sealed class ForwardResolver : IDomainMessageMiddleware
{
    private readonly IDomainMessageMiddleware _inner;
    private readonly IInternalDomainClient _internalClient;
    private readonly IAuthoritativeZoneStore _authoritativeZones;
    private readonly IOptionsMonitor<DnsConfiguration> _options;

    public ForwardResolver(
        IDomainMessageMiddleware inner,
        IOptionsMonitor<DnsConfiguration> options,
        IInternalDomainClient internalClient,
        IAuthoritativeZoneStore authoritativeZones)
    {
        _inner = inner;
        _internalClient = internalClient;
        _authoritativeZones = authoritativeZones;
        _options = options;
    }

    public async ValueTask<DomainMessage?> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        if (context.UpstreamEndpoints is { Length: > 0 } ||
            context.DomainMessage.Questions.Length == 0)
            return await _inner.ProcessAsync(context, cancellationToken).ConfigureAwait(false);

        var questionName = context.DomainMessage.Questions[0].Name;
        if (_authoritativeZones.FindZone(questionName.ToString()) is not null)
            return await _inner.ProcessAsync(context, cancellationToken).ConfigureAwait(false);

        var endpoints = MatchRoute(questionName, context.ClientEndPoint?.Address);
        if (endpoints is null || endpoints.Length == 0)
            return await _inner.ProcessAsync(context, cancellationToken).ConfigureAwait(false);

        context.AnsweredBy ??= Name;
        return await _internalClient.SendAsync(
            context,
            context.DomainMessage,
            endpoints.ToImmutableArray(),
            cancellationToken);
    }

    private IPEndPoint[]? MatchRoute(DomainLabels name, IPAddress? client)
    {
        var routes = _options.CurrentValue.GetParsedRoutes();
        if (routes.Count == 0)
            return null;

        for (var i = 0; i < name.Labels.Length; i++)
        {
            var suffix = string.Join(".", name.Labels.Skip(i).Select(l => l.Label));
            if (routes.TryGetValue(suffix, out var route) && route.AllowsClient(client))
                return route.Upstreams;
        }

        if (routes.TryGetValue(".", out var defaultRoute) && defaultRoute.AllowsClient(client))
            return defaultRoute.Upstreams;

        return null;
    }

    public string Name { get; } = "Forward Resolver";
    public int Priority { get; } = 500;
}
