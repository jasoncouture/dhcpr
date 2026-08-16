namespace Dhcpr.Dhcp.Core.Pipeline;

public interface IDhcpRequestHandler
{
    int Priority => 0;
    string Name => GetType().Name;
    ValueTask HandleDhcpRequestAsync(DhcpRequestContext context, CancellationToken cancellationToken);
}