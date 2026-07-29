using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Resolvers.Caching;
using Dhcpr.Dns.Core.Validation;

using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

public sealed class DnssecValidationMiddleware : IDomainMessageMiddleware
{
    private readonly IDomainMessageMiddleware _innerMiddleware;
    private readonly DnssecMessageValidator _validator;
    private readonly IDnsResponseCache _cache;
    private readonly ILogger<DnssecValidationMiddleware> _logger;

    public DnssecValidationMiddleware(
        IDomainMessageMiddleware innerMiddleware,
        DnssecMessageValidator validator,
        IDnsResponseCache cache,
        ILogger<DnssecValidationMiddleware> logger)
    {
        _innerMiddleware = innerMiddleware;
        _validator = validator;
        _cache = cache;
        _logger = logger;
    }

    public string Name => _innerMiddleware.Name;
    public int Priority => _innerMiddleware.Priority;

    public async ValueTask<DomainMessage?> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        if (context.DnssecScope is { } scope)
            _validator.EnsureTrustAnchorsLoaded(scope);

        var result = await _innerMiddleware.ProcessAsync(context, cancellationToken).ConfigureAwait(false);
        if (result is null)
            return null;

        // Never copy upstream / cache AD — AD is set only from local scope status below.
        result = result with { Flags = result.Flags with { Authentic = false } };

        if (context.DnssecScope is null)
            return result;

        var question = context.DomainMessage.Questions.Length > 0
            ? context.DomainMessage.Questions[0]
            : null;
        var before = context.DnssecScope.Status;

        // Validate even on cache hits: RRSIGs are retained in cache, so crypto can
        // re-verify and load DNSKEY/DS into scope without a network fetch for the answer.
        await _validator.ValidateResponseAsync(context, result, cancellationToken).ConfigureAwait(false);

        if (!context.CacheHit && !context.DoNotCacheResponse)
            _cache.UpdateSecurityStatus(context.DomainMessage, context.DnssecScope.Status);

        var after = context.DnssecScope.Status;
        _logger.LogDebug(
            "DNSSEC {Hop} {Name}/{Type} rcode={Rcode} status {Before} -> {After} (depth={Depth}, cache={Cache})",
            context.IsInternal ? "hop" : "client",
            question?.Name.ToString(),
            question?.Type,
            result.Flags.ResponseCode,
            before,
            after,
            context.InternalHopDepth,
            context.CacheHit);

        if (context.IsInternal)
            return result;

        if (context.DnssecScope.Status == DnssecValidationStatus.Bogus)
        {
            if (!context.DomainMessage.Flags.CheckingDisabled)
            {
                _logger.LogDebug(
                    "DNSSEC SERVFAIL {Name}/{Type}: validation bogus (CD=0)",
                    question?.Name.ToString(),
                    question?.Type);
                return DomainMessage.CreateResponse(
                    context.DomainMessage,
                    DomainResourceRecords.Empty,
                    DomainResponseCode.ServerFailure);
            }

            _logger.LogDebug(
                "DNSSEC returning bogus answer for {Name}/{Type} (CD=1)",
                question?.Name.ToString(),
                question?.Type);
            return result;
        }

        // Client AD only when the whole query (including CNAME chase hops) is Secure.
        if (context.DnssecScope.Status == DnssecValidationStatus.Secure)
        {
            _logger.LogDebug("DNSSEC setting AD for {Name}/{Type}", question?.Name.ToString(), question?.Type);
            result = result with { Flags = result.Flags with { Authentic = true } };
        }

        return result;
    }
}
