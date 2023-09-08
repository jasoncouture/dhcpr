namespace Dhcpr.Peering.Discovery;

public sealed class StaticConfiguration
{
    public Uri[] Peers { get; set; } = Array.Empty<Uri>();
}