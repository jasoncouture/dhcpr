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
        var directed = !upstreamEndpoints.IsDefaultOrEmpty;
        var depth = parentContext.InternalHopDepth + (directed ? 0 : 1);

        if (!directed)
        {
            if (depth > MaxInternalHops)
                return ServFailAsync(message);

            if (parentContext.WorkBudget is { } budget && !budget.TryConsume())
                return ServFailAsync(message);
        }

        ImmutableArray<IPEndPoint>? endpoints = directed ? upstreamEndpoints : null;

        var context = new DomainMessageContext(
            parentContext.ClientEndPoint,
            parentContext.ServerEndPoint,
            message)
        {
            UpstreamEndpoints = endpoints,
            IsInternal = true,
            InternalHopDepth = directed ? parentContext.InternalHopDepth : depth,
            DnssecScope = parentContext.DnssecScope,
            WorkBudget = parentContext.WorkBudget,
            // Directed hops are "ask these nameservers". A cache keyed only by
            // QNAME+QTYPE would replay a parent referral when we later ask the child
            // the same NS/SOA/DNSKEY question (google.com NS → no ANSWER, no AD).
            BypassCache = parentContext.BypassCache || directed
        };

        return EnqueueAsync(context, cancellationToken);
    }

    private static ValueTask<DomainMessage> ServFailAsync(DomainMessage message)
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
