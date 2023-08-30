namespace Dhcpr.Server;

public sealed class ServerConfiguration
{
    public string DnsConfigurationFile { get; set; } = "dns.json";
    public string DhcpConfigurationFile { get; set; } = "dhcp.json";
}