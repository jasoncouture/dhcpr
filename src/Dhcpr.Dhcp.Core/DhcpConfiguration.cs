using Dhcpr.Core;

namespace Dhcpr.Dhcp.Core;

public sealed class DhcpConfiguration : IValidateSelf
{
    public required SubnetConfiguration[] Subnets { get; set; }
    public bool Enabled { get; set; }
    public bool Validate()
    {
        return Subnets.All(subnet => subnet.Validate());
    }
}