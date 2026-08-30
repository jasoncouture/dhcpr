using System.Net.Sockets;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed record TcpDnsPacketReceivedMessage(
    DomainMessageContext Context,
    TcpClient Client,
    Stream Stream) : DnsPacketReceivedMessage(Context)
{
    public TaskCompletionSource SendCompleted { get; } = new(TaskCreationOptions.RunContinuationsAsynchronously);
}