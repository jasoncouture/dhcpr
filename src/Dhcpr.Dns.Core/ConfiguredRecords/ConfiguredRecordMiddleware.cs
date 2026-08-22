using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Resolvers.Caching;

using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.ConfiguredRecords;

/// <summary>
/// Sparse config-record overlay (AA A/AAAA/CNAME/NS + wildcards).
/// Runs before DynDNS so hard-set records win.
/// </summary>
public sealed class ConfiguredRecordMiddleware : IDomainMessageMiddleware, IDisposable
{
    public const int MiddlewarePriority = 150;

    private readonly IDnsResponseCache _cache;
    private readonly IDisposable? _subscription;
    private ParsedConfiguredRecordIndex _index;

    public ConfiguredRecordMiddleware(
        IOptionsMonitor<DnsConfiguration> options,
        IDnsResponseCache cache)
    {
        _cache = cache;
        _index = options.CurrentValue.GetParsedRecords();
        _subscription = options.OnChange(OnOptionsChanged);
    }

    public string Name => "Configured Records";
    // After directed upstream (100), before DynDNS (200).
    public int Priority => MiddlewarePriority;

    public async ValueTask<DomainMessage?> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        await Task.Yield();
        if (context.UpstreamEndpoints is { Length: > 0 })
            return null;

        var answer = _index.TryAnswer(context.DomainMessage, context.ClientEndPoint?.Address);
        if (answer is null)
            return null;

        context.DoNotCacheResponse = true;
        return answer with { Id = context.DomainMessage.Id };
    }

    public void Dispose() => _subscription?.Dispose();

    private void OnOptionsChanged(DnsConfiguration configuration)
    {
        _index = configuration.GetParsedRecords();
        _cache.Clear();
    }
}
