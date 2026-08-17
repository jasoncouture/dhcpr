using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// NXDOMAIN for configured blackhole suffixes (and their subdomains) before
/// cache or upstream — used to sinkhole attack domains.
/// </summary>
public sealed class BlackholeDomainMiddleware : IDomainMessageMiddleware
{
    private readonly IDomainMessageMiddleware _inner;
    private readonly IOptionsMonitor<DnsConfiguration> _options;

    public BlackholeDomainMiddleware(
        IDomainMessageMiddleware inner,
        IOptionsMonitor<DnsConfiguration> options)
    {
        _inner = inner;
        _options = options;
    }

    public string Name => _inner.Name;
    public int Priority => _inner.Priority;

    public async ValueTask<DomainMessage?> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        var blackholes = _options.CurrentValue.BlackholeDomains;
        if (blackholes is { Length: > 0 })
        {
            foreach (var question in context.DomainMessage.Questions)
            {
                if (!IsBlackholed(question.Name, blackholes))
                    continue;

                context.AnsweredBy = "Blackhole";
                return DomainMessage.CreateResponse(
                    context.DomainMessage,
                    DomainResourceRecords.Empty,
                    DomainResponseCode.NameError);
            }
        }

        return await _inner.ProcessAsync(context, cancellationToken);
    }

    internal static bool IsBlackholed(DomainLabels name, string[] blackholes)
    {
        var qname = name.ToString();
        foreach (var suffix in blackholes)
        {
            if (qname.Equals(suffix, StringComparison.OrdinalIgnoreCase))
                return true;
            if (qname.Length > suffix.Length + 1 &&
                qname.EndsWith($".{suffix}", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }
}
