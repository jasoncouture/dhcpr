using System.Collections.Immutable;
using System.Net;

using Dhcpr.Core.Queue;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class InternalDomainClientTests
{
    [Fact]
    public async Task SendAsync_AbortsWithServerFailure_WhenHopDepthExceedsLimit()
    {
        var queue = new CountingQueue();
        var client = new InternalDomainClient(queue.Queue);
        var parent = new DomainMessageContext(null, null, DomainMessage.CreateRequest("a2.info.afilias-nst.info"))
        {
            InternalHopDepth = InternalDomainClient.MaxInternalHops
        };

        var result = await client.SendAsync(
            parent,
            DomainMessage.CreateRequest("a2.info.afilias-nst.info"),
            CancellationToken.None);

        Assert.Equal(DomainResponseCode.ServerFailure, result.Flags.ResponseCode);
        Assert.Equal(0, queue.EnqueueCount);
    }

    [Fact]
    public async Task SendAsync_DirectedUpstream_DoesNotConsumeBudgetOrIncrementDepth()
    {
        var queue = new CountingQueue();
        var client = new InternalDomainClient(queue.Queue);
        var budget = new QueryWorkBudget(limit: 1);
        var parent = new DomainMessageContext(null, null, DomainMessage.CreateRequest("example.com"))
        {
            InternalHopDepth = 3,
            WorkBudget = budget
        };

        var sendTask = client.SendAsync(
            parent,
            DomainMessage.CreateRequest("ns.example.com"),
            ImmutableArray.Create(new IPEndPoint(IPAddress.Loopback, 53)),
            CancellationToken.None).AsTask();

        Assert.Equal(1, queue.EnqueueCount);
        Assert.NotNull(queue.LastMessage);
        Assert.Equal(3, queue.LastMessage!.Context.InternalHopDepth);
        Assert.Same(budget, queue.LastMessage.Context.WorkBudget);
        Assert.True(queue.LastMessage.Context.BypassCache);
        Assert.True(budget.TryConsume());

        queue.LastMessage.TaskCompletionSource.TrySetResult(
            DomainMessage.CreateResponse(
                queue.LastMessage.Context.DomainMessage,
                DomainResourceRecords.Empty,
                DomainResponseCode.NoError));

        await sendTask;
    }

    [Fact]
    public async Task SendAsync_Undirected_IncrementsHopDepthAndConsumesBudget()
    {
        var queue = new CountingQueue();
        var client = new InternalDomainClient(queue.Queue);
        var budget = new QueryWorkBudget(limit: 1);
        var parent = new DomainMessageContext(null, null, DomainMessage.CreateRequest("example.com"))
        {
            InternalHopDepth = 3,
            WorkBudget = budget
        };

        var sendTask = client.SendAsync(
            parent,
            DomainMessage.CreateRequest("ns.example.com"),
            CancellationToken.None).AsTask();

        Assert.Equal(1, queue.EnqueueCount);
        Assert.Equal(4, queue.LastMessage!.Context.InternalHopDepth);
        Assert.False(queue.LastMessage.Context.BypassCache);
        Assert.False(budget.TryConsume());

        queue.LastMessage.TaskCompletionSource.TrySetResult(
            DomainMessage.CreateResponse(
                queue.LastMessage.Context.DomainMessage,
                DomainResourceRecords.Empty,
                DomainResponseCode.NoError));

        await sendTask;
    }

    [Fact]
    public async Task SendAsync_AbortsWithServerFailure_WhenWorkBudgetExhausted()
    {
        var queue = new CountingQueue();
        var client = new InternalDomainClient(queue.Queue);
        var parent = new DomainMessageContext(null, null, DomainMessage.CreateRequest("a2.info.afilias-nst.info"))
        {
            WorkBudget = new QueryWorkBudget(limit: 0)
        };

        var result = await client.SendAsync(
            parent,
            DomainMessage.CreateRequest("a2.info.afilias-nst.info"),
            CancellationToken.None);

        Assert.Equal(DomainResponseCode.ServerFailure, result.Flags.ResponseCode);
        Assert.Equal(0, queue.EnqueueCount);
    }

    private sealed class CountingQueue
    {
        public IMessageQueue<DnsPacketReceivedMessage> Queue { get; }
        public int EnqueueCount { get; private set; }
        public InternalDnsRequestReceivedMessage? LastMessage { get; private set; }

        public CountingQueue()
        {
            var queue = Substitute.For<IMessageQueue<DnsPacketReceivedMessage>>();
            queue.When(q => q.Enqueue(Arg.Any<DnsPacketReceivedMessage>(), Arg.Any<CancellationToken>()))
                .Do(ci =>
                {
                    EnqueueCount++;
                    LastMessage = (InternalDnsRequestReceivedMessage)ci.Arg<DnsPacketReceivedMessage>();
                });
            Queue = queue;
        }
    }
}
