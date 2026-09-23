using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Resolvers.Caching;
using Dhcpr.Dns.Core.Validation;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

public sealed partial class DnssecValidationMiddleware : IDomainMessageMiddleware
{
    private readonly IDomainMessageMiddleware _innerMiddleware;
    private readonly IDnssecMessageValidator _validator;
    private readonly IDnsResponseCache _cache;
    private readonly IOptionsMonitor<DnsConfiguration> _options;
    private readonly ILogger<DnssecValidationMiddleware> _logger;

    public DnssecValidationMiddleware(
        IDomainMessageMiddleware innerMiddleware,
        IDnssecMessageValidator validator,
        IDnsResponseCache cache,
        IOptionsMonitor<DnsConfiguration> options,
        ILogger<DnssecValidationMiddleware> logger)
    {
        _innerMiddleware = innerMiddleware;
        _validator = validator;
        _cache = cache;
        _options = options;
        _logger = logger;
    }

    public string Name => _innerMiddleware.Name;
    public int Priority => _innerMiddleware.Priority;

    public async ValueTask<DomainMessage> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        var dnssecEnabled = _options.CurrentValue.Dnssec?.Enabled ?? true;

        var result = await _innerMiddleware.ProcessAsync(context, cancellationToken).ConfigureAwait(false);

        // Never copy upstream / cache AD — AD is set only from local scope status below.
        result = result with { Flags = result.Flags with { Authentic = false } };

        if (!dnssecEnabled || context.DnssecScope is null)
            return result;

        var question = context.DomainMessage.Questions.Length > 0
            ? context.DomainMessage.Questions[0]
            : null;
        var name = question?.Name;

        // DNSKEY/DS fetches set SuppressKeyFetch and share this scope. Nested hop
        // validation would call EnsureZoneKeysAvailable → false → Bogus and poison
        // the client query permanently (Combine never clears Bogus). Auth of the
        // fetched material is done by DnssecMessageValidator after the fetch returns.
        if (context.DnssecScope.SuppressKeyFetch)
        {
            LogSkipHopValidation(_logger, name, question?.Type);
            return result;
        }

        var before = context.DnssecScope.Status;

        // Cache already stored the validation outcome. Trust it — do not
        // re-run RRSIG crypto on the hit path. Unchecked (legacy) entries
        // still go through the validator once so status can be written.
        if (context.CacheHit && context.CachedDnssecStatus is not DnssecValidationStatus.Unchecked)
            context.DnssecScope.Observe(context.CachedDnssecStatus);
        else
        {
            _validator.EnsureTrustAnchorsLoaded(context.DnssecScope);
            await _validator.ValidateResponseAsync(context, result, cancellationToken).ConfigureAwait(false);

            // Unchecked hits (a refresh stored the RRset before validation, or a
            // legacy entry) must record the outcome. Otherwise every later hit
            // rebuilds canonical records and verifies RRSIGs again.
            if (!context.DoNotCacheResponse)
                _cache.UpdateSecurityStatus(context.DomainMessage, context.DnssecScope.Status);
        }

        var after = context.DnssecScope.Status;

        // Hop noise stays at Debug; client outcomes that matter are louder below.
        if (context.IsInternal)
        {
            LogHopStatus(
                _logger,
                name,
                question?.Type,
                result.Flags.ResponseCode,
                before,
                after,
                context.InternalHopDepth,
                context.CacheHit);
            return result;
        }

        LogClientStatus(
            _logger,
            name,
            question?.Type,
            result.Flags.ResponseCode,
            before,
            after,
            context.CacheHit);

        if (context.DnssecScope.Status == DnssecValidationStatus.Bogus)
        {
            if (!context.DomainMessage.Flags.CheckingDisabled)
            {
                LogServFailBogus(_logger, name, question?.Type);
                context.ServFailReason = $"DNSSEC validation bogus for {name}/{question?.Type}";
                return DomainMessage.CreateResponse(
                    context.DomainMessage,
                    DomainResourceRecords.Empty,
                    DomainResponseCode.ServerFailure);
            }

            LogReturningBogusAnswer(_logger, name, question?.Type);
            return result;
        }

        // Client AD only when the whole query (including CNAME chase hops) is Secure.
        if (context.DnssecScope.Status == DnssecValidationStatus.Secure)
        {
            LogSettingAuthenticData(_logger, name, question?.Type);
            result = result with { Flags = result.Flags with { Authentic = true } };
        }

        return result;
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC skip hop validation during key/DS fetch for {Name}/{Type}")]
    private static partial void LogSkipHopValidation(ILogger logger, DomainLabels? name, DomainRecordType? type);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC hop {Name}/{Type} rcode={Rcode} status {Before} -> {After} (depth={Depth}, cache={Cache})")]
    private static partial void LogHopStatus(
        ILogger logger,
        DomainLabels? name,
        DomainRecordType? type,
        DomainResponseCode rcode,
        DnssecValidationStatus before,
        DnssecValidationStatus after,
        int depth,
        bool cache);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC client {Name}/{Type} rcode={Rcode} status {Before} -> {After} (cache={Cache})")]
    private static partial void LogClientStatus(
        ILogger logger,
        DomainLabels? name,
        DomainRecordType? type,
        DomainResponseCode rcode,
        DnssecValidationStatus before,
        DnssecValidationStatus after,
        bool cache);

    [LoggerMessage(Level = LogLevel.Warning, Message = "DNSSEC SERVFAIL {Name}/{Type}: validation bogus (CD=0)")]
    private static partial void LogServFailBogus(ILogger logger, DomainLabels? name, DomainRecordType? type);

    [LoggerMessage(Level = LogLevel.Warning, Message = "DNSSEC returning bogus answer for {Name}/{Type} (CD=1)")]
    private static partial void LogReturningBogusAnswer(ILogger logger, DomainLabels? name, DomainRecordType? type);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC setting AD for {Name}/{Type}")]
    private static partial void LogSettingAuthenticData(ILogger logger, DomainLabels? name, DomainRecordType? type);
}
