using System.Net.Sockets;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed record UdpDnsPacketReceivedMessage
    (DomainMessageContext Context, UdpClient Client) : DnsPacketReceivedMessage(Context);