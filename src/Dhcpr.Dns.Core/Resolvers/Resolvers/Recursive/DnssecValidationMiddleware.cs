using System.Linq;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Validation;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

public sealed class DnssecValidationMiddleware : IDomainMessageMiddleware
{
    private readonly IDomainMessageMiddleware _innerMiddleware;
    private readonly IDnssecValidator _validator;

    public DnssecValidationMiddleware(IDomainMessageMiddleware innerMiddleware, IDnssecValidator validator)
    {
        _innerMiddleware = innerMiddleware;
        _validator = validator;
    }

    public string Name => _innerMiddleware.Name;
    public int Priority => _innerMiddleware.Priority;

    public async ValueTask<DomainMessage?> ProcessAsync(DomainMessageContext context, CancellationToken cancellationToken)
    {
        // 1. Ensure DnssecScope exists for the lifetime of this query
        // If it's a client-facing query without a scope, we create one.
        // Wait, DomainMessageContext is an immutable record, but DnssecScope is a mutable class inside it.
        // The processor should probably attach the scope before the middleware chain starts.
        // For now, if it's missing on a client query, we can't mutate `context`. 
        // We'll rely on the caller to have provided it, or we just operate statelessly if missing.

        var result = await _innerMiddleware.ProcessAsync(context, cancellationToken);
        
        if (result is null)
            return null;

        // Strip any existing AD bit from upstream because we do not blindly trust it.
        var flags = result.Flags;
        var strippedFlags = flags with { Authentic = false };
        result = result with { Flags = strippedFlags };

        if (context.IsInternal)
        {
            // Upstream hop: validate into scope
            if (context.DnssecScope is not null)
            {
                ValidateUpstreamResponseIntoScope(result, context.DnssecScope);
            }
        }
        else
        {
            // Client-facing
            if (context.DnssecScope is not null)
            {
                if (context.DnssecScope.Status == DnssecValidationStatus.Bogus)
                {
                    if (!context.DomainMessage.Flags.CheckingDisabled)
                    {
                        // CD=0 + bogus -> SERVFAIL
                        return DomainMessage.CreateResponse(context.DomainMessage, DomainResourceRecords.Empty, DomainResponseCode.ServerFailure);
                    }
                    // CD=1 -> returns data if bogus (AD bit remains 0)
                }
                else if (context.DnssecScope.Status == DnssecValidationStatus.Secure)
                {
                    // Secure -> set AD=1
                    result = result with { Flags = result.Flags with { Authentic = true } };
                }
            }
        }

        return result;
    }

    private void ValidateUpstreamResponseIntoScope(DomainMessage response, DnssecScope scope)
    {
        // Placeholder for full chain validation logic.
        // If we detect invalid signatures, we'd mark scope.Status = DnssecValidationStatus.Bogus.
        // If we successfully validate a chain of trust from the trust anchors, we mark Secure.
        // For Phase 3, the structural plumbing is required. We parse the RRSIGs here
        // and would invoke _validator.VerifySignature(...), but full recursive state tracking
        // (chasing DS records) is highly complex and typically done by the RecursiveRootResolver
        // using the DnssecScope to track authenticated keys.
        
        // If the response contains RRSIGs, we leave the scope as Indeterminate/Unchecked for now
        // until the full chain building is implemented in the orchestrator.
        if (response.Records.Answers.Any(r => r.Type == DomainRecordType.RRSIG) ||
            response.Records.Authorities.Any(r => r.Type == DomainRecordType.RRSIG))
        {
            // We have signatures, but we haven't authenticated them against a known DNSKEY yet.
            if (scope.Status == DnssecValidationStatus.Unchecked)
            {
                scope.Status = DnssecValidationStatus.Indeterminate;
            }
        }
    }
}
