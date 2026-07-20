using System.Net;

using Dhcpr.Core.Queue;

namespace Dhcpr.Dns.Core.Protocol.Processing;

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
        await using var registration = cancellationToken.Register(
            static state =>
            {
                var tcs = (TaskCompletionSource<DomainMessage?>)state!;
                tcs.TrySetCanceled();
            },
            message.TaskCompletionSource);

        _messageQueue.Enqueue(message, cancellationToken);

        DomainMessage? result;
        try
        {
            result = await message.TaskCompletionSource.Task.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }

        if (result is null)
            throw new OperationCanceledException("Did not receive a response from the internal DNS chain");

        return result;
    }
}