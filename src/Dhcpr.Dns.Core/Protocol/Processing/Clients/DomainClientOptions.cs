using System.Net;

namespace Dhcpr.Dns.Core.Protocol.Processing.Clients;

public readonly record struct DomainClientOptions()
{
    internal static IPEndPoint DefaultEndPoint { get; } = new IPEndPoint(IPAddress.Any, 53);
    public IPEndPoint EndPoint { get; init; } = DefaultEndPoint;
    public DomainClientType Type { get; init; } = DomainClientType.Udp;
    public TimeSpan TimeOut { get; init; } = TimeSpan.FromSeconds(3);

    public static DomainClientOptions Default { get; } = new();
}