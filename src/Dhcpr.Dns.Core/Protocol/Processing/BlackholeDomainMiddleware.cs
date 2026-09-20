using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// NXDOMAIN for configured blackhole suffixes and regexes before upstream.
/// Lives inside the response cache so a name pays the regex once.
/// </summary>
public sealed class BlackholeDomainMiddleware : IDomainMessageMiddleware
{
    private readonly IDomainMessageMiddleware _inner;
    private readonly IOptionsMonitor<DnsConfiguration> _options;

    private string[]? _cachedDomains;
    private BlackholeRuleSet _rules = BlackholeRuleSet.Empty;

    public BlackholeDomainMiddleware(
        IDomainMessageMiddleware inner,
        IOptionsMonitor<DnsConfiguration> options)
    {
        _inner = inner;
        _options = options;
    }

    public string Name => _inner.Name;
    public int Priority => _inner.Priority;

    public async ValueTask<DomainMessage> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        var rules = CurrentRules();
        if (!rules.IsEmpty)
        {
            foreach (var question in context.DomainMessage.Questions)
            {
                if (!rules.Matches(question.Name))
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
        => BlackholeRuleSet.TryCreate(blackholes, out _, out var rules) && rules.Matches(name);

    private BlackholeRuleSet CurrentRules()
    {
        var config = _options.CurrentValue;
        var compiled = config.GetBlackholeRules();
        if (!compiled.IsEmpty || config.BlackholeDomains is not { Length: > 0 })
            return compiled;

        var domains = config.BlackholeDomains;
        if (ReferenceEquals(domains, _cachedDomains))
            return _rules;

        if (!BlackholeRuleSet.TryCreate(domains, out _, out var rules))
            return BlackholeRuleSet.Empty;

        _cachedDomains = domains;
        _rules = rules;
        return _rules;
    }
}
