namespace Dhcpr.Dhcp.Core;

public static class DhcpGlobals
{
    public static Guid ServerId { get; } = Guid.NewGuid();
}