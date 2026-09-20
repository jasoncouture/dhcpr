using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

/// <summary>
/// Retries inner resolution when it returns SERVFAIL, before the cache stores a result.
/// Transient upstream/DNSSEC flakiness should not become the permanent client answer
/// (and must not be what systemd-resolved negative-caches).
/// </summary>
public sealed class ServFailRetryDecorator : IDomainMessageMiddleware
{
    public const int MaxAttempts = 3;

    private readonly IDomainMessageMiddleware _innerMiddleware;

    public ServFailRetryDecorator(IDomainMessageMiddleware innerMiddleware)
    {
        _innerMiddleware = innerMiddleware;
    }

    public string Name => _innerMiddleware.Name;
    public int Priority => _innerMiddleware.Priority;

    public async ValueTask<DomainMessage> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        DomainMessage result = default!;
        for (var attempt = 1; attempt <= MaxAttempts; attempt++)
        {
            if (attempt > 1)
                context.DnssecScope?.ResetStatus();

            result = await _innerMiddleware.ProcessAsync(context, cancellationToken).ConfigureAwait(false);
            if (result.Flags.ResponseCode is not DomainResponseCode.ServerFailure)
                return result;
        }

        return result;
    }
}
