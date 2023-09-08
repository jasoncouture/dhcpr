namespace Dhcpr.Dhcp.Core.Pipeline;

public class DhcpLoggingRequestHandler : IDhcpRequestHandler
{
    public ValueTask HandleDhcpRequest(DhcpRequestContext context, CancellationToken cancellationToken)
    {
        return ValueTask.CompletedTask;
    }
}