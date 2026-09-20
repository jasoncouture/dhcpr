using Dhcpr.Dns.Core.Authoritative;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.DynamicDns;

/// <summary>
/// Exact-name DynDNS overlay (AA A/AAAA). Decorator around the remaining
/// walk so local updates win over forward/recurse. Directed hops skip.
/// </summary>
public sealed class DynamicDnsMiddleware : IDomainMessageMiddleware
{
    private readonly IDomainMessageMiddleware _inner;
    private readonly IDynamicDnsStore _store;
    private readonly IAuthoritativeZoneStore _zones;

    public DynamicDnsMiddleware(
        IDomainMessageMiddleware inner,
        IDynamicDnsStore store,
        IAuthoritativeZoneStore zones)
    {
        _inner = inner;
        _store = store;
        _zones = zones;
    }

    public string Name => "Dynamic DNS";
    // After directed upstream (100), before forward (500) / recursive (5000).
    public int Priority => 200;

    public async ValueTask<DomainMessage?> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        if (
            context.UpstreamEndpoints is { Length: > 0 } ||
            DynamicDnsAnswerer.TryAnswer(_store, _zones, context.DomainMessage) is not { } answer
            )
            return await _inner.ProcessAsync(context, cancellationToken).ConfigureAwait(false);

        context.DoNotCacheResponse = true;
        context.AnsweredBy ??= Name;
        return answer with { Id = context.DomainMessage.Id };
    }
}
