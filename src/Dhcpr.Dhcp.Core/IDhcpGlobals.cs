namespace Dhcpr.Dhcp.Core;

/// <summary>
/// Process-wide DHCP server identity.
/// </summary>
public interface IDhcpGlobals
{
    Guid ServerId { get; }
}
