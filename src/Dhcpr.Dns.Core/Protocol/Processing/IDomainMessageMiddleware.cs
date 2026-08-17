namespace Dhcpr.Dns.Core.Protocol.Processing;

public interface IDomainMessageMiddleware
{
    /// <summary>
    /// Attempts to produce a response for <paramref name="context"/>.
    /// Returns <see langword="null"/> to pass the request to the next middleware.
    /// </summary>
    public ValueTask<DomainMessage?> ProcessAsync(DomainMessageContext context, CancellationToken cancellationToken);

    /// <summary>
    /// Display name for logs. Defaults to the implementing type name.
    /// </summary>
    string Name => GetType().Name;

    /// <summary>
    /// Pipeline order. Lower values run first. Default is 0.
    /// </summary>
    int Priority => 0;
}