using System.Net;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public readonly record struct DomainClientOptions()
{
    internal static readonly IPEndPoint DefaultEndPoint = new IPEndPoint(IPAddress.Any, 53);
    public IPEndPoint EndPoint { get; init; } = DefaultEndPoint;
    public DomainClientType Type { get; init; } = DomainClientType.Udp;
    public TimeSpan TimeOut { get; init; } = TimeSpan.FromMilliseconds(250);

    public static DomainClientOptions Default { get; } = new();
}