using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Validation;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

public sealed class DnssecValidationMiddleware : IDomainMessageMiddleware
{
    private readonly IDomainMessageMiddleware _innerMiddleware;
    private readonly DnssecMessageValidator _validator;

    public DnssecValidationMiddleware(
        IDomainMessageMiddleware innerMiddleware,
        DnssecMessageValidator validator)
    {
        _innerMiddleware = innerMiddleware;
        _validator = validator;
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

        await _validator.ValidateResponseAsync(context, result, cancellationToken).ConfigureAwait(false);

        if (context.IsInternal)
            return result;

        if (context.DnssecScope.Status == DnssecValidationStatus.Bogus)
        {
            if (!context.DomainMessage.Flags.CheckingDisabled)
            {
                return DomainMessage.CreateResponse(
                    context.DomainMessage,
                    DomainResourceRecords.Empty,
                    DomainResponseCode.ServerFailure);
            }

            return result;
        }

        if (context.DnssecScope.Status == DnssecValidationStatus.Secure)
            result = result with { Flags = result.Flags with { Authentic = true } };

        return result;
    }
}
