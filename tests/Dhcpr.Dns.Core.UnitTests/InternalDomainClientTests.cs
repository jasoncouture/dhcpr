using System.Collections.Immutable;
using System.Net;

using Dhcpr.Core.Queue;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.UnitTests;

public class InternalDomainClientTests
{
    [Fact]
    public async Task SendAsync_AbortsWithServerFailure_WhenHopDepthExceedsLimit()
    {
        var queue = new CountingQueue();
        var client = new InternalDomainClient(queue);
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
    public async Task SendAsync_PropagatesHopDepth_OnReentry()
    {
        var queue = new CountingQueue();
        var client = new InternalDomainClient(queue);
        var parent = new DomainMessageContext(null, null, DomainMessage.CreateRequest("example.com"))
        {
            InternalHopDepth = 3
        };

        var sendTask = client.SendAsync(
            parent,
            DomainMessage.CreateRequest("ns.example.com"),
            ImmutableArray.Create(new IPEndPoint(IPAddress.Loopback, 53)),
            CancellationToken.None).AsTask();

        Assert.Equal(1, queue.EnqueueCount);
        Assert.NotNull(queue.LastMessage);
        Assert.Equal(4, queue.LastMessage!.Context.InternalHopDepth);
        Assert.True(queue.LastMessage.Context.IsInternal);

        queue.LastMessage.TaskCompletionSource.TrySetResult(
            DomainMessage.CreateResponse(
                queue.LastMessage.Context.DomainMessage,
                DomainResourceRecords.Empty,
                DomainResponseCode.NoError));

        await sendTask;
    }

    private sealed class CountingQueue : IMessageQueue<DnsPacketReceivedMessage>
    {
        public int EnqueueCount { get; private set; }
        public InternalDnsRequestReceivedMessage? LastMessage { get; private set; }

        public void Enqueue(DnsPacketReceivedMessage item, CancellationToken cancellationToken = default)
        {
            EnqueueCount++;
            LastMessage = (InternalDnsRequestReceivedMessage)item;
        }

        public ValueTask<QueueItem<DnsPacketReceivedMessage>> DequeueAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }
}
