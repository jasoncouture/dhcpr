using System.Net;

using Dhcpr.Core.Queue;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Parser;
using Dhcpr.Dns.Core.Protocol.Processing;

using Microsoft.Extensions.Options;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class DnsQueryExecutorTests
{
    [Fact]
    public async Task ExecuteAsync_EmptyRequest_ReturnsEmptyStatus()
    {
        var executor = CreateExecutor(new CountingQueue().Queue);

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
        var executor = CreateExecutor(new CountingQueue().Queue, maxRequestBytes: 12);
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
        var executor = CreateExecutor(new CountingQueue().Queue);

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
        var executor = CreateExecutor(queue.Queue);
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
        Assert.Equal(DnsQuerySource.Doh, queue.LastMessage.Context.Source);
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

    [Fact]
    public async Task QueryAsync_QueuesRequestAndReturnsResponse()
    {
        var queue = new CountingQueue();
        var executor = CreateExecutor(queue.Queue);
        var request = DomainMessage.CreateRequest("health.example");

        var queryTask = executor.QueryAsync(request, CancellationToken.None).AsTask();

        Assert.Equal(1, queue.EnqueueCount);
        Assert.NotNull(queue.LastMessage);
        Assert.Equal("health.example", queue.LastMessage!.Context.DomainMessage.Questions[0].Name.ToString());
        Assert.True(queue.LastMessage.Context.BypassCache);
        Assert.True(queue.LastMessage.Context.DoNotCacheResponse);

        var response = DomainMessage.CreateResponse(
            queue.LastMessage.Context.DomainMessage,
            DomainResourceRecords.Empty,
            DomainResponseCode.NoError);
        queue.LastMessage.TaskCompletionSource.TrySetResult(response);

        var result = await queryTask;
        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NoError, result!.Flags.ResponseCode);
    }

    private static IDnsQueryExecutor CreateExecutor(
        IMessageQueue<DnsPacketReceivedMessage> queue,
        int maxRequestBytes = 65535)
    {
        var options = Options.Create(new DnsConfiguration
        {
            DnsOverHttp = new DnsOverHttpConfiguration
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

    private sealed class CountingQueue
    {
        public IMessageQueue<DnsPacketReceivedMessage> Queue { get; }
        public int EnqueueCount { get; private set; }
        public HttpDnsPacketReceivedMessage? LastMessage { get; private set; }

        public CountingQueue()
        {
            var queue = Substitute.For<IMessageQueue<DnsPacketReceivedMessage>>();
            queue.When(q => q.Enqueue(Arg.Any<DnsPacketReceivedMessage>(), Arg.Any<CancellationToken>()))
                .Do(ci =>
                {
                    EnqueueCount++;
                    LastMessage = (HttpDnsPacketReceivedMessage)ci.Arg<DnsPacketReceivedMessage>();
                });
            Queue = queue;
        }
    }
}
