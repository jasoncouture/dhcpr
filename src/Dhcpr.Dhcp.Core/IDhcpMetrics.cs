using Dhcpr.Dhcp.Core.Pipeline;

namespace Dhcpr.Dhcp.Core;

public interface IDhcpMetrics
{
    void RecordMessage(DhcpRequestContext context);
}
