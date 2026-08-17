namespace Dhcpr.Dhcp.Core.Pipeline;

public interface IDhcpRequestHandler
{
    /// <summary>
    /// Pipeline order. Higher values run first. Default is 0.
    /// </summary>
    int Priority => 0;

    /// <summary>
    /// Display name for logs. Defaults to the implementing type name.
    /// </summary>
    string Name => GetType().Name;

    /// <summary>
    /// Handles one DHCP request. Implementations may mutate or cancel <paramref name="context"/>.
    /// </summary>
    ValueTask HandleDhcpRequestAsync(DhcpRequestContext context, CancellationToken cancellationToken);
}