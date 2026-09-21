using System.Collections.Immutable;
using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.UnitTests;

public class InternalDomainClientTests
{
    [Fact]
    public async Task SendAsync_AbortsWithServerFailure_WhenHopDepthExceedsLimit()
    {
        var pipeline = new CountingPipeline();
        var client = new InternalDomainClient(pipeline);
        var parent = new DomainMessageContext(null, null, DomainMessage.CreateRequest("a2.info.afilias-nst.info"))
        {
            InternalHopDepth = InternalDomainClient.MaxInternalHops
        };

        var result = await client.SendAsync(
            parent,
            DomainMessage.CreateRequest("a2.info.afilias-nst.info"),
            CancellationToken.None);

        Assert.Equal(DomainResponseCode.ServerFailure, result.Flags.ResponseCode);
        Assert.Equal(0, pipeline.ExecuteCount);
    }

    [Fact]
    public async Task SendAsync_DirectedUpstream_DoesNotConsumeBudgetOrIncrementDepth()
    {
        var pipeline = new CountingPipeline();
        var client = new InternalDomainClient(pipeline);
        var budget = new QueryWorkBudget(limit: 1);
        var tips = new NameserverTipCache();
        var parent = new DomainMessageContext(null, null, DomainMessage.CreateRequest("example.com"))
        {
            InternalHopDepth = 3,
            WorkBudget = budget,
            NameserverTips = tips,
            ClientCookie = ImmutableArray.Create<byte>(1, 2, 3, 4, 5, 6, 7, 8)
        };

        var sendTask = client.SendAsync(
            parent,
            DomainMessage.CreateRequest("ns.example.com"),
            ImmutableArray.Create(new IPEndPoint(IPAddress.Loopback, 53)),
            CancellationToken.None).AsTask();

        Assert.Equal(1, pipeline.ExecuteCount);
        Assert.NotNull(pipeline.LastContext);
        Assert.Equal(3, pipeline.LastContext!.InternalHopDepth);
        Assert.Same(budget, pipeline.LastContext.WorkBudget);
        Assert.Same(tips, pipeline.LastContext.NameserverTips);
        Assert.True(pipeline.LastContext.BypassCache);
        Assert.True(pipeline.LastContext.DoNotCacheResponse);
        Assert.Equal(parent.ClientCookie, pipeline.LastContext.ClientCookie);
        Assert.True(budget.TryConsume());

        pipeline.CompleteLast(
            DomainMessage.CreateResponse(
                pipeline.LastContext.DomainMessage,
                DomainResourceRecords.Empty,
                DomainResponseCode.NoError));

        await sendTask;
    }

    [Fact]
    public async Task SendAsync_Undirected_IncrementsHopDepthAndConsumesBudget()
    {
        var pipeline = new CountingPipeline();
        var client = new InternalDomainClient(pipeline);
        var budget = new QueryWorkBudget(limit: 1);
        var parent = new DomainMessageContext(null, null, DomainMessage.CreateRequest("example.com"))
        {
            InternalHopDepth = 3,
            WorkBudget = budget,
            Source = DnsQuerySource.Doh
        };

        var sendTask = client.SendAsync(
            parent,
            DomainMessage.CreateRequest("ns.example.com"),
            CancellationToken.None).AsTask();

        Assert.Equal(1, pipeline.ExecuteCount);
        Assert.Equal(4, pipeline.LastContext!.InternalHopDepth);
        Assert.False(pipeline.LastContext.BypassCache);
        Assert.Equal(DnsQuerySource.Doh, pipeline.LastContext.Source);
        Assert.False(budget.TryConsume());

        pipeline.CompleteLast(
            DomainMessage.CreateResponse(
                pipeline.LastContext.DomainMessage,
                DomainResourceRecords.Empty,
                DomainResponseCode.NoError));

        await sendTask;
    }

    [Fact]
    public async Task SendAsync_AbortsWithServerFailure_WhenWorkBudgetExhausted()
    {
        var pipeline = new CountingPipeline();
        var client = new InternalDomainClient(pipeline);
        var parent = new DomainMessageContext(null, null, DomainMessage.CreateRequest("a2.info.afilias-nst.info"))
        {
            WorkBudget = new QueryWorkBudget(limit: 0)
        };

        var result = await client.SendAsync(
            parent,
            DomainMessage.CreateRequest("a2.info.afilias-nst.info"),
            CancellationToken.None);

        Assert.Equal(DomainResponseCode.ServerFailure, result.Flags.ResponseCode);
        Assert.Equal(0, pipeline.ExecuteCount);
    }

    [Fact]
    public async Task SendPrefetchAsync_UsesOwnScopeAndSetsSuppressAddressPrefetch()
    {
        var pipeline = new CountingPipeline();
        var client = new InternalDomainClient(pipeline);
        var parentScope = new DnssecScope();
        var parentBudget = new QueryWorkBudget(limit: 0);
        var parent = new DomainMessageContext(null, null, DomainMessage.CreateRequest("example.com"))
        {
            InternalHopDepth = InternalDomainClient.MaxInternalHops,
            DnssecScope = parentScope,
            WorkBudget = parentBudget
        };

        var sendTask = client.SendPrefetchAsync(
            parent,
            DomainMessage.CreateRequest("example.com", DomainRecordType.AAAA),
            CancellationToken.None).AsTask();

        Assert.Equal(1, pipeline.ExecuteCount);
        Assert.NotNull(pipeline.LastContext);
        Assert.True(pipeline.LastContext!.IsInternal);
        Assert.True(pipeline.LastContext.SuppressAddressPrefetch);
        Assert.Equal(1, pipeline.LastContext.InternalHopDepth);
        Assert.NotSame(parentScope, pipeline.LastContext.DnssecScope);
        Assert.NotSame(parentBudget, pipeline.LastContext.WorkBudget);
        Assert.False(pipeline.LastContext.BypassCache);

        pipeline.CompleteLast(
            DomainMessage.CreateResponse(
                pipeline.LastContext.DomainMessage,
                DomainResourceRecords.Empty,
                DomainResponseCode.NoError));

        await sendTask;
    }

    [Fact]
    public async Task SendRefreshAsync_BypassesCacheAndUsesOwnScope()
    {
        var pipeline = new CountingPipeline();
        var client = new InternalDomainClient(pipeline);
        var parentScope = new DnssecScope();
        var parentBudget = new QueryWorkBudget(limit: 0);
        var parent = new DomainMessageContext(null, null, DomainMessage.CreateRequest("example.com"))
        {
            InternalHopDepth = InternalDomainClient.MaxInternalHops,
            DnssecScope = parentScope,
            WorkBudget = parentBudget
        };

        var sendTask = client.SendRefreshAsync(
            parent,
            DomainMessage.CreateRequest("example.com", DomainRecordType.A),
            CancellationToken.None).AsTask();

        Assert.Equal(1, pipeline.ExecuteCount);
        Assert.NotNull(pipeline.LastContext);
        Assert.True(pipeline.LastContext!.BypassCache);
        Assert.True(pipeline.LastContext.IsInternal);
        Assert.True(pipeline.LastContext.SuppressAddressPrefetch);
        Assert.NotSame(parentScope, pipeline.LastContext.DnssecScope);
        Assert.NotSame(parentBudget, pipeline.LastContext.WorkBudget);

        pipeline.CompleteLast(
            DomainMessage.CreateResponse(
                pipeline.LastContext.DomainMessage,
                DomainResourceRecords.Empty,
                DomainResponseCode.NoError));

        await sendTask;
    }

    [Fact]
    public async Task SendAsync_CoalescesIdenticalDirectedHops()
    {
        var pipeline = new CountingPipeline();
        var client = new InternalDomainClient(pipeline);
        var endpoints = ImmutableArray.Create(
            new IPEndPoint(IPAddress.Parse("192.0.2.1"), 53),
            new IPEndPoint(IPAddress.Parse("192.0.2.2"), 53));
        var shuffled = ImmutableArray.Create(endpoints[1], endpoints[0]);
        var parent = new DomainMessageContext(null, null, DomainMessage.CreateRequest("example.com"))
        {
            QueryCoalescer = new QueryCoalescer()
        };
        var request = DomainMessage.CreateRequest("ntpns.org", DomainRecordType.NS);

        var first = client.SendAsync(parent, request, endpoints, CancellationToken.None).AsTask();
        var second = client.SendAsync(parent, request, shuffled, CancellationToken.None).AsTask();

        Assert.Equal(1, pipeline.ExecuteCount);
        Assert.NotNull(pipeline.LastContext);

        var response = DomainMessage.CreateResponse(
            pipeline.LastContext!.DomainMessage,
            DomainResourceRecords.Empty,
            DomainResponseCode.NoError);
        pipeline.CompleteLast(response);

        Assert.Same(response, await first);
        Assert.Same(response, await second);
    }

    [Fact]
    public async Task SendAsync_DoesNotCoalesceDifferentQuestions()
    {
        var pipeline = new CountingPipeline();
        var client = new InternalDomainClient(pipeline);
        var endpoints = ImmutableArray.Create(new IPEndPoint(IPAddress.Loopback, 53));
        var parent = new DomainMessageContext(null, null, DomainMessage.CreateRequest("example.com"))
        {
            QueryCoalescer = new QueryCoalescer()
        };

        var first = client.SendAsync(
            parent,
            DomainMessage.CreateRequest("a.ntpns.org"),
            endpoints,
            CancellationToken.None).AsTask();
        var second = client.SendAsync(
            parent,
            DomainMessage.CreateRequest("b.ntpns.org"),
            endpoints,
            CancellationToken.None).AsTask();

        Assert.Equal(2, pipeline.ExecuteCount);
        foreach (var completion in pipeline.Completions)
        {
            var context = pipeline.Contexts[pipeline.Completions.IndexOf(completion)];
            completion.TrySetResult(
                DomainMessage.CreateResponse(
                    context.DomainMessage,
                    DomainResourceRecords.Empty,
                    DomainResponseCode.NoError));
        }

        await first;
        await second;
    }

    private sealed class CountingPipeline : IDnsQueryPipeline
    {
        public int ExecuteCount { get; private set; }
        public DomainMessageContext? LastContext { get; private set; }
        public List<DomainMessageContext> Contexts { get; } = [];
        public List<TaskCompletionSource<DomainMessage?>> Completions { get; } = [];

        public ValueTask<DomainMessage?> ExecuteAsync(
            DomainMessageContext context,
            CancellationToken cancellationToken)
        {
            ExecuteCount++;
            LastContext = context;
            Contexts.Add(context);
            var tcs = new TaskCompletionSource<DomainMessage?>(TaskCreationOptions.RunContinuationsAsynchronously);
            Completions.Add(tcs);
            return new ValueTask<DomainMessage?>(tcs.Task);
        }

        public void CompleteLast(DomainMessage response)
            => Completions[^1].TrySetResult(response);
    }
}
