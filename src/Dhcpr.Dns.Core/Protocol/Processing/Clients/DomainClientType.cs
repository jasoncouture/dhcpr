namespace Dhcpr.Dns.Core.Protocol.Processing.Clients;

[Flags]
public enum DomainClientType
{
    Udp = 1,
    Tcp = 2,
    Internal = 4
}