namespace Dhcpr.Dhcp.Core.Pipeline;

public sealed class DhcpLoggingRequestHandler : IDhcpRequestHandler
{
    public int Priority => -100;
    public ValueTask HandleDhcpRequestAsync(DhcpRequestContext context, CancellationToken cancellationToken)
    {
        return ValueTask.CompletedTask;
    }
}