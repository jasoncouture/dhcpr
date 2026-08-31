using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.ConfiguredRecords;

/// <summary>
/// Sparse config-record overlay (AA A/AAAA/CNAME/NS + wildcards).
/// Runs before DynDNS so hard-set records win.
/// </summary>
public sealed class ConfiguredRecordMiddleware : IDomainMessageMiddleware
{
    public const int MiddlewarePriority = 150;

    private readonly IOptionsMonitor<DnsConfiguration> _options;

    public ConfiguredRecordMiddleware(IOptionsMonitor<DnsConfiguration> options)
    {
        _options = options;
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

        var answer = _options.CurrentValue.GetParsedRecords()
            .TryAnswer(context.DomainMessage, context.ClientEndPoint?.Address);
        if (answer is null)
            return null;

        context.DoNotCacheResponse = true;
        return answer with { Id = context.DomainMessage.Id };
    }
}
