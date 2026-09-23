using System.Collections.Immutable;
using System.Net;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public class InternalDomainClient : IInternalDomainClient
{
    public const int MaxInternalHops = 20;

    private readonly IDnsQueryPipeline _pipeline;

    public InternalDomainClient(IDnsQueryPipeline pipeline)
    {
        _pipeline = pipeline;
    }

    private static readonly IPEndPoint _internalEndPoint = new(IPAddress.Any, 53);

    public async ValueTask<DomainMessage> SendAsync(DomainMessage domainMessage, CancellationToken cancellationToken)
        => await ExecutePipelineAsync(
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
        if (parentContext.QueryCoalescer is { } coalescer && !message.Questions.IsDefaultOrEmpty)
        {
            return await coalescer.JoinAsync(
                message.Questions[0],
                upstreamEndpoints,
                token => SendUncoalescedAsync(parentContext, message, upstreamEndpoints, token).AsTask(),
                cancellationToken);
        }

        return await SendUncoalescedAsync(parentContext, message, upstreamEndpoints, cancellationToken);
    }

    private async ValueTask<DomainMessage> SendUncoalescedAsync(
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
            QueryCoalescer = parentContext.QueryCoalescer,
            // Directed hops are "ask these nameservers". A cache keyed only by
            // QNAME+QTYPE would replay a parent referral when we later ask the child
            // the same NS/SOA/DNSKEY question (google.com NS → no ANSWER, no AD).
            BypassCache = parentContext.BypassCache || directed,
            Source = parentContext.Source,
            ParentTraceContext = DnsInstrumentation.CaptureContext(),
            ClientCookie = parentContext.ClientCookie
        };

        return await ExecutePipelineAsync(context, cancellationToken);
    }

    public async ValueTask<DomainMessage> SendPrefetchAsync(
        DomainMessageContext parentContext,
        DomainMessage message,
        CancellationToken cancellationToken)
    {
        if (parentContext.QueryCoalescer is { } coalescer && !message.Questions.IsDefaultOrEmpty)
        {
            return await coalescer.JoinAsync(
                message.Questions[0],
                endpoints: default,
                token => SendPrefetchUncoalescedAsync(parentContext, message, token).AsTask(),
                cancellationToken);
        }

        return await SendPrefetchUncoalescedAsync(parentContext, message, cancellationToken);
    }

    private async ValueTask<DomainMessage> SendPrefetchUncoalescedAsync(
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
            QueryCoalescer = parentContext.QueryCoalescer,
            SuppressAddressPrefetch = true,
            Source = parentContext.Source,
            ParentTraceContext = DnsInstrumentation.CaptureContext(),
            ClientCookie = parentContext.ClientCookie
        };

        return await ExecutePipelineAsync(context, cancellationToken);
    }

    public async ValueTask<DomainRefreshResult> SendRefreshAsync(
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
            QueryCoalescer = new QueryCoalescer(),
            BypassCache = true,
            SuppressAddressPrefetch = true,
            Source = parentContext.Source,
            ParentTraceContext = DnsInstrumentation.CaptureContext(),
            ClientCookie = parentContext.ClientCookie
        };

        var response = await ExecutePipelineAsync(context, cancellationToken);
        return new DomainRefreshResult(response, context.DnssecScope.Status);
    }

    private static DomainMessage ServFail(DomainMessage message)
        => DomainMessage.CreateResponse(
            message,
            DomainResourceRecords.Empty,
            DomainResponseCode.ServerFailure);

    private async ValueTask<DomainMessage> ExecutePipelineAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        var result = await _pipeline.ExecuteAsync(context, cancellationToken).ConfigureAwait(false);
        if (result is null)
            throw new OperationCanceledException("Did not receive a response from the internal DNS chain");

        return result;
    }
}
