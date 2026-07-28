using Dhcpr.Dns.Core.Authoritative;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.DynamicDns;

/// <summary>
/// Exact-name DynDNS overlay (AA A/AAAA). Runs before forward/recurse so local updates win.
/// </summary>
public sealed class DynamicDnsMiddleware : IDomainMessageMiddleware
{
    private readonly DynamicDnsStore _store;
    private readonly AuthoritativeZoneStore _zones;

    public DynamicDnsMiddleware(DynamicDnsStore store, AuthoritativeZoneStore zones)
    {
        _store = store;
        _zones = zones;
    }

    public string Name => "Dynamic DNS";
    // After directed upstream (100), before forward (500) / recursive (5000).
    public int Priority => 200;

    public ValueTask<DomainMessage?> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        if (context.UpstreamEndpoints is { Length: > 0 })
            return ValueTask.FromResult<DomainMessage?>(null);

        var answer = DynamicDnsAnswerer.TryAnswer(_store, _zones, context.DomainMessage);
        if (answer is null)
            return ValueTask.FromResult<DomainMessage?>(null);

        context.DoNotCacheResponse = true;
        return ValueTask.FromResult<DomainMessage?>(answer with { Id = context.DomainMessage.Id });
    }
}
