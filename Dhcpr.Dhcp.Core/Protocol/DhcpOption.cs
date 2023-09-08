namespace Dhcpr.Dhcp.Core.Protocol;

public record DhcpOption(DhcpOptionType Type, byte[] Payload);