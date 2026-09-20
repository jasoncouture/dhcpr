using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.ConfiguredRecords;

/// <summary>
/// Sparse config-record overlay (AA A/AAAA/CNAME/NS + wildcards).
/// Decorator around Root Zone so hard-set records win over primed root data.
/// </summary>
public sealed class ConfiguredRecordMiddleware : IDomainMessageMiddleware
{
    public const int MiddlewarePriority = 150;

    private readonly IDomainMessageMiddleware _inner;
    private readonly IOptionsMonitor<DnsConfiguration> _options;

    public ConfiguredRecordMiddleware(
        IDomainMessageMiddleware inner,
        IOptionsMonitor<DnsConfiguration> options)
    {
        _inner = inner;
        _options = options;
    }

    public string Name => "Configured Records";
    public int Priority => MiddlewarePriority;

    public async ValueTask<DomainMessage> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        if (
            context.UpstreamEndpoints is { Length: > 0 } || 
            _options.CurrentValue.GetParsedRecords().TryAnswer(context.DomainMessage, context.ClientEndPoint?.Address) is not {} answer
            )
            return await _inner.ProcessAsync(context, cancellationToken).ConfigureAwait(false);

        context.DoNotCacheResponse = true;
        context.AnsweredBy ??= Name;
        return answer with { Id = context.DomainMessage.Id };
    }
}
