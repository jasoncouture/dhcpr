using Dhcpr.Dns.Core.Authoritative;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.DynamicDns;

/// <summary>
/// Exact-name DynDNS overlay (AA A/AAAA). Runs before forward/recurse so local updates win.
/// </summary>
public sealed class DynamicDnsMiddleware : IDomainMessageMiddleware
{
    private readonly IDynamicDnsStore _store;
    private readonly IAuthoritativeZoneStore _zones;

    public DynamicDnsMiddleware(IDynamicDnsStore store, IAuthoritativeZoneStore zones)
    {
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
        await Task.Yield();
        if (context.UpstreamEndpoints is { Length: > 0 })
            return null;

        var answer = DynamicDnsAnswerer.TryAnswer(_store, _zones, context.DomainMessage);
        if (answer is null)
            return null;

        context.DoNotCacheResponse = true;
        return answer with { Id = context.DomainMessage.Id };
    }
}
