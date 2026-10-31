using System.Collections.Immutable;
using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.Processing.Clients;
using Dhcpr.Dns.Core.Protocol.Processing.LiveQueries;
using Dhcpr.Dns.Core.Protocol.Processing.Dnssec;
using Dhcpr.Dns.Core.Protocol.Processing.Referral;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class InternalDomainClientTests
{
    [Fact]
    public async Task SendAsync_AbortsWithServerFailure_WhenHopDepthExceedsLimit()
    {
        var contexts = new List<DomainMessageContext>();
        var completions = new List<TaskCompletionSource<DomainMessage?>>();
        var pipeline = HeldPipeline(contexts, completions);
        var client = new InternalDomainClient(pipeline, Substitute.For<IEdnsLoopTag>());
        var parent = new DomainMessageContext(null, null, DomainMessage.CreateRequest("a2.info.afilias-nst.info"))
        {
            InternalHopDepth = InternalDomainClient.MaxInternalHops
        };

        var result = await client.SendAsync(
            parent,
            DomainMessage.CreateRequest("a2.info.afilias-nst.info"),
            CancellationToken.None);

        Assert.Equal(DomainResponseCode.ServerFailure, result.Flags.ResponseCode);
        Assert.Empty(contexts);
    }

    [Fact]
    public async Task SendAsync_DirectedUpstream_DoesNotConsumeBudgetOrIncrementDepth()
    {
        var contexts = new List<DomainMessageContext>();
        var completions = new List<TaskCompletionSource<DomainMessage?>>();
        var pipeline = HeldPipeline(contexts, completions);
        var client = new InternalDomainClient(pipeline, Substitute.For<IEdnsLoopTag>());
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

        Assert.Single(contexts);
        Assert.NotNull(contexts[^1]);
        Assert.Equal(3, contexts[^1].InternalHopDepth);
        Assert.Same(budget, contexts[^1].WorkBudget);
        Assert.Same(tips, contexts[^1].NameserverTips);
        Assert.True(contexts[^1].BypassCache);
        Assert.True(contexts[^1].DoNotCacheResponse);
        Assert.Equal(parent.ClientCookie, contexts[^1].ClientCookie);
        Assert.True(budget.TryConsume());

        completions[^1].TrySetResult(
            DomainMessage.CreateResponse(
                contexts[^1].DomainMessage,
                DomainResourceRecords.Empty,
                DomainResponseCode.NoError));

        await sendTask;
    }

    [Fact]
    public async Task SendAsync_Undirected_IncrementsHopDepthAndConsumesBudget()
    {
        var contexts = new List<DomainMessageContext>();
        var completions = new List<TaskCompletionSource<DomainMessage?>>();
        var pipeline = HeldPipeline(contexts, completions);
        var client = new InternalDomainClient(pipeline, Substitute.For<IEdnsLoopTag>());
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

        Assert.Single(contexts);
        Assert.Equal(4, contexts[^1].InternalHopDepth);
        Assert.False(contexts[^1].BypassCache);
        Assert.Equal(DnsQuerySource.Doh, contexts[^1].Source);
        Assert.False(budget.TryConsume());

        completions[^1].TrySetResult(
            DomainMessage.CreateResponse(
                contexts[^1].DomainMessage,
                DomainResourceRecords.Empty,
                DomainResponseCode.NoError));

        await sendTask;
    }

    [Fact]
    public async Task SendAsync_AbortsWithServerFailure_WhenWorkBudgetExhausted()
    {
        var contexts = new List<DomainMessageContext>();
        var completions = new List<TaskCompletionSource<DomainMessage?>>();
        var pipeline = HeldPipeline(contexts, completions);
        var client = new InternalDomainClient(pipeline, Substitute.For<IEdnsLoopTag>());
        var parent = new DomainMessageContext(null, null, DomainMessage.CreateRequest("a2.info.afilias-nst.info"))
        {
            WorkBudget = new QueryWorkBudget(limit: 0)
        };

        var result = await client.SendAsync(
            parent,
            DomainMessage.CreateRequest("a2.info.afilias-nst.info"),
            CancellationToken.None);

        Assert.Equal(DomainResponseCode.ServerFailure, result.Flags.ResponseCode);
        Assert.Empty(contexts);
    }

    [Fact]
    public async Task SendPrefetchAsync_UsesOwnScopeAndSetsSuppressAddressPrefetch()
    {
        var contexts = new List<DomainMessageContext>();
        var completions = new List<TaskCompletionSource<DomainMessage?>>();
        var pipeline = HeldPipeline(contexts, completions);
        var client = new InternalDomainClient(pipeline, Substitute.For<IEdnsLoopTag>());
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

        Assert.Single(contexts);
        Assert.NotNull(contexts[^1]);
        Assert.True(contexts[^1].IsInternal);
        Assert.True(contexts[^1].SuppressAddressPrefetch);
        Assert.Equal(1, contexts[^1].InternalHopDepth);
        Assert.NotSame(parentScope, contexts[^1].DnssecScope);
        Assert.NotSame(parentBudget, contexts[^1].WorkBudget);
        Assert.False(contexts[^1].BypassCache);

        completions[^1].TrySetResult(
            DomainMessage.CreateResponse(
                contexts[^1].DomainMessage,
                DomainResourceRecords.Empty,
                DomainResponseCode.NoError));

        await sendTask;
    }

    [Fact]
    public async Task SendRefreshAsync_BypassesCacheAndUsesOwnScope()
    {
        var contexts = new List<DomainMessageContext>();
        var completions = new List<TaskCompletionSource<DomainMessage?>>();
        var pipeline = HeldPipeline(contexts, completions);
        var client = new InternalDomainClient(pipeline, Substitute.For<IEdnsLoopTag>());
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

        Assert.Single(contexts);
        Assert.NotNull(contexts[^1]);
        Assert.True(contexts[^1].BypassCache);
        Assert.True(contexts[^1].IsInternal);
        Assert.True(contexts[^1].SuppressAddressPrefetch);
        Assert.NotSame(parentScope, contexts[^1].DnssecScope);
        Assert.NotSame(parentBudget, contexts[^1].WorkBudget);

        completions[^1].TrySetResult(
            DomainMessage.CreateResponse(
                contexts[^1].DomainMessage,
                DomainResourceRecords.Empty,
                DomainResponseCode.NoError));

        await sendTask;
    }

    [Fact]
    public async Task SendAsync_CoalescesIdenticalDirectedHops()
    {
        var contexts = new List<DomainMessageContext>();
        var completions = new List<TaskCompletionSource<DomainMessage?>>();
        var pipeline = HeldPipeline(contexts, completions);
        var client = new InternalDomainClient(pipeline, Substitute.For<IEdnsLoopTag>());
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

        Assert.Single(contexts);
        Assert.NotNull(contexts[^1]);

        var response = DomainMessage.CreateResponse(
            contexts[^1].DomainMessage,
            DomainResourceRecords.Empty,
            DomainResponseCode.NoError);
        completions[^1].TrySetResult(response);

        Assert.Same(response, await first);
        Assert.Same(response, await second);
    }

    [Fact]
    public async Task SendAsync_DoesNotCoalesceDifferentQuestions()
    {
        var contexts = new List<DomainMessageContext>();
        var completions = new List<TaskCompletionSource<DomainMessage?>>();
        var pipeline = HeldPipeline(contexts, completions);
        var client = new InternalDomainClient(pipeline, Substitute.For<IEdnsLoopTag>());
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

        Assert.Equal(2, contexts.Count);
        foreach (var completion in completions)
        {
            var context = contexts[completions.IndexOf(completion)];
            completion.TrySetResult(
                DomainMessage.CreateResponse(
                    context.DomainMessage,
                    DomainResourceRecords.Empty,
                    DomainResponseCode.NoError));
        }

        await first;
        await second;
    }

    [Fact]
    public async Task SendAsync_SameQuestionReusesTheSelfQueryCookie()
    {
        var calls = 0;
        var clock = Substitute.For<TimeProvider>();
        clock.GetUtcNow().Returns(_ =>
        {
            calls++;
            return new DateTimeOffset(2026, 10, 15, 12, 0, 0, TimeSpan.Zero);
        });
        var secrets = Substitute.For<IDnsServerCookieSecretSource>();
        var secret = Enumerable.Range(1, 32).Select(i => (byte)i).ToArray();
        secrets.TryGetSecret(out Arg.Any<ReadOnlyMemory<byte>>())
            .Returns(call =>
            {
                call[0] = new ReadOnlyMemory<byte>(secret);
                return true;
            });
        IEdnsLoopTag tag = new EdnsLoopTag(secrets, clock);
        var contexts = new List<DomainMessageContext>();
        var completions = new List<TaskCompletionSource<DomainMessage?>>();
        var pipeline = HeldPipeline(contexts, completions);
        var client = new InternalDomainClient(pipeline, tag);
        var parent = new DomainMessageContext(null, null, DomainMessage.CreateRequest("example.com"));
        var endpoints = ImmutableArray.Create(new IPEndPoint(IPAddress.Loopback, 53));

        var first = client.SendAsync(
            parent,
            DomainMessage.CreateRequest("example.com"),
            endpoints,
            CancellationToken.None).AsTask();
        var second = client.SendAsync(
            parent,
            DomainMessage.CreateRequest("Example.COM"),
            endpoints,
            CancellationToken.None).AsTask();
        var glue = client.SendAsync(
            parent,
            DomainMessage.CreateRequest("ns.example.com"),
            endpoints,
            CancellationToken.None).AsTask();

        Assert.Equal(1, calls);
        Assert.NotNull(parent.SelfQueryCookie);
        Assert.Equal(parent.SelfQueryCookie, contexts[0].SelfQueryCookie);
        Assert.Equal(parent.SelfQueryCookie, contexts[1].SelfQueryCookie);
        Assert.Null(contexts[2].SelfQueryCookie);

        foreach (var completion in completions)
        {
            var context = contexts[completions.IndexOf(completion)];
            completion.TrySetResult(
                DomainMessage.CreateResponse(
                    context.DomainMessage,
                    DomainResourceRecords.Empty,
                    DomainResponseCode.NoError));
        }

        await first;
        await second;
        await glue;
    }

    private static IDnsQueryPipeline HeldPipeline(
        List<DomainMessageContext> contexts,
        List<TaskCompletionSource<DomainMessage?>> completions)
    {
        var pipeline = Substitute.For<IDnsQueryPipeline>();
        pipeline.ExecuteAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                contexts.Add(call.Arg<DomainMessageContext>());
                var completion = new TaskCompletionSource<DomainMessage?>(
                    TaskCreationOptions.RunContinuationsAsynchronously);
                completions.Add(completion);
                return new ValueTask<DomainMessage?>(completion.Task);
            });
        return pipeline;
    }
}
