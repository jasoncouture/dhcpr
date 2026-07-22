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
        var result = await _innerMiddleware.ProcessAsync(context, cancellationToken);
        
        if (result is null)
            return null;

        var flags = result.Flags;
        var strippedFlags = flags with { Authentic = false };
        result = result with { Flags = strippedFlags };

        if (context.IsInternal)
        {
            if (context.DnssecScope is not null)
            {
                ValidateUpstreamResponseIntoScope(result, context.DnssecScope);
            }
        }
        else
        {
            if (context.DnssecScope is not null)
            {
                if (context.DnssecScope.Status == DnssecValidationStatus.Bogus)
                {
                    if (!context.DomainMessage.Flags.CheckingDisabled)
                    {
                        return DomainMessage.CreateResponse(context.DomainMessage, DomainResourceRecords.Empty, DomainResponseCode.ServerFailure);
                    }
                }
                else if (context.DnssecScope.Status == DnssecValidationStatus.Secure)
                {
                    result = result with { Flags = result.Flags with { Authentic = true } };
                }
            }
        }

        return result;
    }

    private void ValidateUpstreamResponseIntoScope(DomainMessage response, DnssecScope scope)
    {
        if (response.Records.Answers.Any(r => r.Type == DomainRecordType.RRSIG) ||
            response.Records.Authorities.Any(r => r.Type == DomainRecordType.RRSIG))
        {
            if (scope.Status == DnssecValidationStatus.Unchecked)
            {
                scope.Status = DnssecValidationStatus.Indeterminate;
            }
        }
    }
}
