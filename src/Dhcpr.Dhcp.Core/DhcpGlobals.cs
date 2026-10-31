namespace Dhcpr.Dhcp.Core;

/// <inheritdoc cref="IDhcpGlobals"/>
public sealed class DhcpGlobals : IDhcpGlobals
{
    public Guid ServerId { get; } = Guid.NewGuid();
}
