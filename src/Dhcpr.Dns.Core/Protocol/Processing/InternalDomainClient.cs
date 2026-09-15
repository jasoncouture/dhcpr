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

    private static readonly IPEndPoint _internalEndPoint = new(IPAddress.Any, 53);

    public async ValueTask<DomainMessage> SendAsync(DomainMessage domainMessage, CancellationToken cancellationToken)
        => await EnqueueAsync(
            new DomainMessageContext(_internalEndPoint, _internalEndPoint, domainMessage)
            {
                IsInternal = true,
                InternalHopDepth = 1,
                ParentTraceContext = DnsInstrumentation.CaptureContext()
            },
            cancellationToken);

    public async ValueTask<DomainMessage> SendAsync(
        DomainMessageContext parentContext,
        DomainMessage message,
        CancellationToken cancellationToken)
        => await SendAsync(parentContext, message, upstreamEndpoints: default, cancellationToken);

    public async ValueTask<DomainMessage> SendAsync(
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
                return ServFail(message);

            if (parentContext.WorkBudget is { } budget && !budget.TryConsume())
                return ServFail(message);
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
            NameserverTips = parentContext.NameserverTips,
            // Directed hops are "ask these nameservers". A cache keyed only by
            // QNAME+QTYPE would replay a parent referral when we later ask the child
            // the same NS/SOA/DNSKEY question (google.com NS → no ANSWER, no AD).
            BypassCache = parentContext.BypassCache || directed,
            Source = parentContext.Source,
            ParentTraceContext = DnsInstrumentation.CaptureContext()
        };

        return await EnqueueAsync(context, cancellationToken);
    }

    public async ValueTask<DomainMessage> SendPrefetchAsync(
        DomainMessageContext parentContext,
        DomainMessage message,
        CancellationToken cancellationToken)
    {
        var context = new DomainMessageContext(
            parentContext.ClientEndPoint,
            parentContext.ServerEndPoint,
            message)
        {
            IsInternal = true,
            InternalHopDepth = 1,
            DnssecScope = new DnssecScope(),
            WorkBudget = new QueryWorkBudget(),
            NameserverTips = parentContext.NameserverTips ?? new NameserverTipCache(),
            SuppressAddressPrefetch = true,
            Source = parentContext.Source,
            ParentTraceContext = DnsInstrumentation.CaptureContext()
        };

        return await EnqueueAsync(context, cancellationToken);
    }

    private static DomainMessage ServFail(DomainMessage message)
        => DomainMessage.CreateResponse(
            message,
            DomainResourceRecords.Empty,
            DomainResponseCode.ServerFailure);

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
