using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Validation;

using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

public sealed class DnssecValidationMiddleware : IDomainMessageMiddleware
{
    private readonly IDomainMessageMiddleware _innerMiddleware;
    private readonly DnssecMessageValidator _validator;
    private readonly ILogger<DnssecValidationMiddleware> _logger;

    public DnssecValidationMiddleware(
        IDomainMessageMiddleware innerMiddleware,
        DnssecMessageValidator validator,
        ILogger<DnssecValidationMiddleware> logger)
    {
        _innerMiddleware = innerMiddleware;
        _validator = validator;
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

        // Never copy upstream AD.
        result = result with { Flags = result.Flags with { Authentic = false } };

        if (context.DnssecScope is null)
            return result;

        var question = context.DomainMessage.Questions.Length > 0
            ? context.DomainMessage.Questions[0]
            : null;
        var before = context.DnssecScope.Status;

        await _validator.ValidateResponseAsync(context, result, cancellationToken).ConfigureAwait(false);

        var after = context.DnssecScope.Status;
        _logger.LogInformation(
            "DNSSEC {Hop} {Name}/{Type} rcode={Rcode} status {Before} -> {After} (depth={Depth})",
            context.IsInternal ? "hop" : "client",
            question?.Name,
            question?.Type,
            result.Flags.ResponseCode,
            before,
            after,
            context.InternalHopDepth);

        if (context.IsInternal)
            return result;

        if (context.DnssecScope.Status == DnssecValidationStatus.Bogus)
        {
            if (!context.DomainMessage.Flags.CheckingDisabled)
            {
                _logger.LogInformation(
                    "DNSSEC SERVFAIL {Name}/{Type}: validation bogus (CD=0)",
                    question?.Name,
                    question?.Type);
                return DomainMessage.CreateResponse(
                    context.DomainMessage,
                    DomainResourceRecords.Empty,
                    DomainResponseCode.ServerFailure);
            }

            _logger.LogInformation(
                "DNSSEC returning bogus answer for {Name}/{Type} (CD=1)",
                question?.Name,
                question?.Type);
            return result;
        }

        if (context.DnssecScope.Status == DnssecValidationStatus.Secure)
        {
            _logger.LogInformation("DNSSEC setting AD for {Name}/{Type}", question?.Name, question?.Type);
            result = result with { Flags = result.Flags with { Authentic = true } };
        }

        return result;
    }
}
