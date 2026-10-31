namespace Dhcpr.Dns.Core.Protocol.Processing;

public interface IDomainMessageMiddleware
{
    /// <summary>
    /// Produces a response for <paramref name="context"/>.
    /// The pipeline always answers; ServerFailure is the terminal fallback.
    /// </summary>
    public ValueTask<DomainMessage> ProcessAsync(DomainMessageContext context, CancellationToken cancellationToken);

    /// <summary>
    /// Display name for logs. Defaults to the implementing type name.
    /// </summary>
    string Name => GetType().Name;

    /// <summary>
    /// Pipeline order. Lower values run first. Default is 0.
    /// </summary>
    int Priority => 0;
}