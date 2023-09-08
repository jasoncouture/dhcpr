namespace Dhcpr.Peering.Discovery;

public class StaticConfiguration
{
    public Uri[] Peers { get; set; } = Array.Empty<Uri>();
}