using System.Net;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public interface IDomainClient
{
    async ValueTask<DomainMessage> SendUdpAsync(
        IPEndPoint target,
        DomainMessage message,
        CancellationToken cancellationToken
    ) => await SendAsync(target, message, false, cancellationToken);

    async ValueTask<DomainMessage> SendTcpAsync(
        IPEndPoint target,
        DomainMessage message,
        CancellationToken cancellationToken
    ) => await SendAsync(target, message, true, cancellationToken);

    ValueTask<DomainMessage> SendAsync(IPEndPoint target, DomainMessage message, bool tcp,
        CancellationToken cancellationToken);
}