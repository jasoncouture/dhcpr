using System.Net;

using Dhcpr.Core.Queue;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public interface IDomainClient : IDisposable
{
    ValueTask<DomainMessage> SendAsync(DomainMessage message,
        CancellationToken cancellationToken);

    void IDisposable.Dispose()
    {
        // ReSharper disable once GCSuppressFinalizeForTypeWithoutDestructor
        GC.SuppressFinalize(this);
    }
}

public interface IInternalDomainClient : IDomainClient
{
}

public class InternalDomainClient : IInternalDomainClient
{
    private readonly IMessageQueue<DnsPacketReceivedMessage> _messageQueue;

    public InternalDomainClient(IMessageQueue<DnsPacketReceivedMessage> messageQueue)
    {
        _messageQueue = messageQueue;
    }

    private static readonly IPEndPoint InternalEndPoint = new(IPAddress.Any, 53);

    public async ValueTask<DomainMessage> SendAsync(DomainMessage domainMessage, CancellationToken cancellationToken)
    {
        var message =
            new InternalDnsRequestReceivedMessage(
                new DomainMessageContext(InternalEndPoint, InternalEndPoint,
                    domainMessage));
        _messageQueue.Enqueue(message, cancellationToken);

        var result = await message.TaskCompletionSource.Task.ConfigureAwait(false);

        if (result is null)
            throw new OperationCanceledException("Did not receive a response from the internal DNS chain");

        return result;
    }
}