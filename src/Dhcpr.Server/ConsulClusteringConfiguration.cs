namespace Dhcpr.Server;

public sealed class ConsulClusteringConfiguration
{
    public string Address { get; set; } = "";

    public string Token { get; set; } = "";

    public string KvRootFolder { get; set; } = "";
}
