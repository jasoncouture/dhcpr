using System.Net;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public record DomainMessageContext(IPEndPoint? ClientEndPoint, IPEndPoint? ServerEndPoint, DomainMessage DomainMessage)
{
    public bool Cancel { get; set; }
}