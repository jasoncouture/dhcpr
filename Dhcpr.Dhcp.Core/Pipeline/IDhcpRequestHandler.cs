namespace Dhcpr.Dhcp.Core.Pipeline;

public interface IDhcpRequestHandler
{
    int Order => 0;
    ValueTask HandleDhcpRequest(DhcpRequestContext context, CancellationToken cancellationToken);
}