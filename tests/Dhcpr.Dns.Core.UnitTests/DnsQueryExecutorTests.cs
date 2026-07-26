using System.Net;

using Dhcpr.Core.Queue;
using Dhcpr.Dns.Core;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Parser;
using Dhcpr.Dns.Core.Protocol.Processing;

using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.UnitTests;

public class DnsQueryExecutorTests
{
    [Fact]
    public async Task ExecuteAsync_EmptyRequest_ReturnsEmptyStatus()
    {
        var executor = CreateExecutor(new CountingQueue());

        var result = await executor.ExecuteAsync(
            ReadOnlyMemory<byte>.Empty,
            new IPEndPoint(IPAddress.Loopback, 1),
            new IPEndPoint(IPAddress.Loopback, 8080),
            CancellationToken.None);

        Assert.Equal(DnsQueryExecutionStatus.EmptyRequest, result.Status);
        Assert.Null(result.ResponseWire);
    }

    [Fact]
    public async Task ExecuteAsync_TooLarge_ReturnsRequestTooLarge()
    {
        var executor = CreateExecutor(new CountingQueue(), maxRequestBytes: 12);
        var wire = new byte[13];

        var result = await executor.ExecuteAsync(
            wire,
            new IPEndPoint(IPAddress.Loopback, 1),
            new IPEndPoint(IPAddress.Loopback, 8080),
            CancellationToken.None);

        Assert.Equal(DnsQueryExecutionStatus.RequestTooLarge, result.Status);
    }

    [Fact]
    public async Task ExecuteAsync_InvalidWire_ReturnsInvalidWireFormat()
    {
        var executor = CreateExecutor(new CountingQueue());

        var result = await executor.ExecuteAsync(
            new byte[] { 1, 2, 3 },
            new IPEndPoint(IPAddress.Loopback, 1),
            new IPEndPoint(IPAddress.Loopback, 8080),
            CancellationToken.None);

        Assert.Equal(DnsQueryExecutionStatus.InvalidWireFormat, result.Status);
    }

    [Fact]
    public async Task ExecuteAsync_QueuesExternalContextAndReturnsEncodedResponse()
    {
        var queue = new CountingQueue();
        var executor = CreateExecutor(queue);
        var request = DomainMessage.CreateRequest("example.com");
        var requestWire = Encode(request);

        var executeTask = executor.ExecuteAsync(
            requestWire,
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 4433),
            new IPEndPoint(IPAddress.Loopback, 8080),
            CancellationToken.None).AsTask();

        Assert.Equal(1, queue.EnqueueCount);
        Assert.NotNull(queue.LastMessage);
        Assert.False(queue.LastMessage!.Context.IsInternal);
        Assert.NotNull(queue.LastMessage.Context.WorkBudget);
        Assert.NotNull(queue.LastMessage.Context.DnssecScope);
        Assert.Equal(IPAddress.Parse("203.0.113.10"), queue.LastMessage.Context.ClientEndPoint!.Address);

        var response = DomainMessage.CreateResponse(
            queue.LastMessage.Context.DomainMessage,
            DomainResourceRecords.Empty,
            DomainResponseCode.NameError);
        queue.LastMessage.TaskCompletionSource.TrySetResult(response);

        var result = await executeTask;
        Assert.Equal(DnsQueryExecutionStatus.Success, result.Status);
        Assert.NotNull(result.ResponseWire);
        var decoded = DomainMessageEncoder.Decode(result.ResponseWire);
        Assert.Equal(DomainResponseCode.NameError, decoded.Flags.ResponseCode);
        Assert.Equal(request.Id, decoded.Id);
    }

    private static IDnsQueryExecutor CreateExecutor(
        IMessageQueue<DnsPacketReceivedMessage> queue,
        int maxRequestBytes = 65535)
    {
        var options = Options.Create(new DnsConfiguration
        {
            DoH = new DoHConfiguration
            {
                MaxRequestBytes = maxRequestBytes
            },
            ListenAddresses = ["udp://127.0.0.1:53"]
        });
        return new DnsQueryExecutor(queue, options);
    }

    private static byte[] Encode(DomainMessage message)
    {
        var buffer = new byte[Math.Max(512, message.EstimatedSize)];
        var length = DomainMessageEncoder.Encode(buffer, message);
        return buffer.AsSpan(0, length).ToArray();
    }

    private sealed class CountingQueue : IMessageQueue<DnsPacketReceivedMessage>
    {
        public int EnqueueCount { get; private set; }
        public HttpDnsPacketReceivedMessage? LastMessage { get; private set; }

        public void Enqueue(DnsPacketReceivedMessage item, CancellationToken cancellationToken = default)
        {
            EnqueueCount++;
            LastMessage = (HttpDnsPacketReceivedMessage)item;
        }

        public ValueTask<QueueItem<DnsPacketReceivedMessage>> DequeueAsync(CancellationToken cancellationToken = default)
            => throw new NotSupportedException();
    }
}
