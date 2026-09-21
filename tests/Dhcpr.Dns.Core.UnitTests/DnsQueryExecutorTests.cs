using System.Net;

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
        var executor = CreateExecutor(new CountingPipeline());

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
        var executor = CreateExecutor(new CountingPipeline(), maxRequestBytes: 12);
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
        var executor = CreateExecutor(new CountingPipeline());

        var result = await executor.ExecuteAsync(
            new byte[] { 1, 2, 3 },
            new IPEndPoint(IPAddress.Loopback, 1),
            new IPEndPoint(IPAddress.Loopback, 8080),
            CancellationToken.None);

        Assert.Equal(DnsQueryExecutionStatus.InvalidWireFormat, result.Status);
    }

    [Fact]
    public async Task ExecuteAsync_RunsPipelineWithExternalContextAndReturnsEncodedResponse()
    {
        var pipeline = new CountingPipeline();
        var executor = CreateExecutor(pipeline);
        var request = DomainMessage.CreateRequest("example.com");
        var requestWire = Encode(request);

        var executeTask = executor.ExecuteAsync(
            requestWire,
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 4433),
            new IPEndPoint(IPAddress.Loopback, 8080),
            CancellationToken.None).AsTask();

        Assert.Equal(1, pipeline.ExecuteCount);
        Assert.NotNull(pipeline.LastContext);
        Assert.False(pipeline.LastContext!.IsInternal);
        Assert.Equal(DnsQuerySource.Doh, pipeline.LastContext.Source);
        Assert.NotNull(pipeline.LastContext.WorkBudget);
        Assert.NotNull(pipeline.LastContext.DnssecScope);
        Assert.Equal(IPAddress.Parse("203.0.113.10"), pipeline.LastContext.ClientEndPoint!.Address);

        var response = DomainMessage.CreateResponse(
            pipeline.LastContext.DomainMessage,
            DomainResourceRecords.Empty,
            DomainResponseCode.NameError);
        pipeline.CompleteLast(response);

        var result = await executeTask;
        Assert.Equal(DnsQueryExecutionStatus.Success, result.Status);
        Assert.NotNull(result.ResponseWire);
        var decoded = DomainMessageEncoder.Decode(result.ResponseWire);
        Assert.Equal(DomainResponseCode.NameError, decoded.Flags.ResponseCode);
        Assert.Equal(request.Id, decoded.Id);
    }

    [Fact]
    public async Task QueryAsync_RunsPipelineAndReturnsResponse()
    {
        var pipeline = new CountingPipeline();
        var executor = CreateExecutor(pipeline);
        var request = DomainMessage.CreateRequest("health.example");

        var queryTask = executor.QueryAsync(request, CancellationToken.None).AsTask();

        Assert.Equal(1, pipeline.ExecuteCount);
        Assert.NotNull(pipeline.LastContext);
        Assert.Equal("health.example", pipeline.LastContext!.DomainMessage.Questions[0].Name.ToString());
        Assert.True(pipeline.LastContext.BypassCache);
        Assert.True(pipeline.LastContext.DoNotCacheResponse);

        var response = DomainMessage.CreateResponse(
            pipeline.LastContext.DomainMessage,
            DomainResourceRecords.Empty,
            DomainResponseCode.NoError);
        pipeline.CompleteLast(response);

        var result = await queryTask;
        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NoError, result!.Flags.ResponseCode);
    }

    private static IDnsQueryExecutor CreateExecutor(
        IDnsQueryPipeline pipeline,
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
        return new DnsQueryExecutor(pipeline, options);
    }

    private static byte[] Encode(DomainMessage message)
    {
        var buffer = new byte[Math.Max(512, message.EstimatedSize)];
        var length = DomainMessageEncoder.Encode(buffer, message);
        return buffer.AsSpan(0, length).ToArray();
    }

    private sealed class CountingPipeline : IDnsQueryPipeline
    {
        public int ExecuteCount { get; private set; }
        public DomainMessageContext? LastContext { get; private set; }
        private TaskCompletionSource<DomainMessage?>? _completion;

        public ValueTask<DomainMessage?> ExecuteAsync(
            DomainMessageContext context,
            CancellationToken cancellationToken)
        {
            ExecuteCount++;
            LastContext = context;
            _completion = new TaskCompletionSource<DomainMessage?>(
                TaskCreationOptions.RunContinuationsAsynchronously);
            return new ValueTask<DomainMessage?>(_completion.Task);
        }

        public void CompleteLast(DomainMessage response)
            => _completion!.TrySetResult(response);
    }
}
