using System.Net.Sockets;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed record TcpDnsPacketReceivedMessage
    (DomainMessageContext Context, TcpClient Client) : DnsPacketReceivedMessage(Context);