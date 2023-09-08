namespace Dhcpr.Dhcp.Core.Pipeline;

public sealed class DhcpLoggingRequestHandler : IDhcpRequestHandler
{
    public int Priority => -100;
    public ValueTask HandleDhcpRequest(DhcpRequestContext context, CancellationToken cancellationToken)
    {
        return ValueTask.CompletedTask;
    }
}