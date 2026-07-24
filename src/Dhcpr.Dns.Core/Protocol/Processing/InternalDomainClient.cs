using System.Collections.Immutable;
using System.Net;

using Dhcpr.Core.Queue;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public class InternalDomainClient : IInternalDomainClient
{
    public const int MaxInternalHops = 20;

    private readonly IMessageQueue<DnsPacketReceivedMessage> _messageQueue;

    public InternalDomainClient(IMessageQueue<DnsPacketReceivedMessage> messageQueue)
    {
        _messageQueue = messageQueue;
    }

    private static readonly IPEndPoint InternalEndPoint = new(IPAddress.Any, 53);

    public ValueTask<DomainMessage> SendAsync(DomainMessage domainMessage, CancellationToken cancellationToken)
        => EnqueueAsync(
            new DomainMessageContext(InternalEndPoint, InternalEndPoint, domainMessage)
            {
                IsInternal = true,
                InternalHopDepth = 1
            },
            cancellationToken);

    public ValueTask<DomainMessage> SendAsync(
        DomainMessageContext parentContext,
        DomainMessage message,
        CancellationToken cancellationToken)
        => SendAsync(parentContext, message, upstreamEndpoints: default, cancellationToken);

    public ValueTask<DomainMessage> SendAsync(
        DomainMessageContext parentContext,
        DomainMessage message,
        ImmutableArray<IPEndPoint> upstreamEndpoints,
        CancellationToken cancellationToken)
    {
        var depth = parentContext.InternalHopDepth + 1;
        if (depth > MaxInternalHops)
            return ServFail(message);

        if (parentContext.WorkBudget is { } budget && !budget.TryConsume())
            return ServFail(message);

        ImmutableArray<IPEndPoint>? endpoints = upstreamEndpoints.IsDefaultOrEmpty
            ? null
            : upstreamEndpoints;

        var context = new DomainMessageContext(
            parentContext.ClientEndPoint,
            parentContext.ServerEndPoint,
            message)
        {
            UpstreamEndpoints = endpoints,
            IsInternal = true,
            InternalHopDepth = depth,
            DnssecScope = parentContext.DnssecScope,
            WorkBudget = parentContext.WorkBudget
        };

        return EnqueueAsync(context, cancellationToken);
    }

    private static ValueTask<DomainMessage> ServFail(DomainMessage message)
        => ValueTask.FromResult(
            DomainMessage.CreateResponse(
                message,
                DomainResourceRecords.Empty,
                DomainResponseCode.ServerFailure));

    private async ValueTask<DomainMessage> EnqueueAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        var message = new InternalDnsRequestReceivedMessage(context);
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
