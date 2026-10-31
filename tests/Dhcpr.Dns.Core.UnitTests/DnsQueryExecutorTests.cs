using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Parser;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.Processing.LiveQueries;
using Dhcpr.Dns.Core.Protocol.Processing.Dnssec;

using Microsoft.Extensions.Options;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class DnsQueryExecutorTests
{
    [Fact]
    public async Task ExecuteAsync_EmptyRequest_ReturnsEmptyStatus()
    {
        var executor = CreateExecutor(Substitute.For<IDnsQueryPipeline>());

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
        var executor = CreateExecutor(Substitute.For<IDnsQueryPipeline>(), maxRequestBytes: 12);
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
        var executor = CreateExecutor(Substitute.For<IDnsQueryPipeline>());

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
        var contexts = new List<DomainMessageContext>();
        var completions = new List<TaskCompletionSource<DomainMessage?>>();
        var pipeline = HeldPipeline(contexts, completions);
        var executor = CreateExecutor(pipeline);
        var request = DomainMessage.CreateRequest("example.com");
        var requestWire = Encode(request);

        var executeTask = executor.ExecuteAsync(
            requestWire,
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 4433),
            new IPEndPoint(IPAddress.Loopback, 8080),
            CancellationToken.None).AsTask();

        var context = Assert.Single(contexts);
        Assert.False(context.IsInternal);
        Assert.Equal(DnsQuerySource.Doh, context.Source);
        Assert.NotNull(context.WorkBudget);
        Assert.NotNull(context.DnssecScope);
        Assert.Equal(IPAddress.Parse("203.0.113.10"), context.ClientEndPoint!.Address);

        var response = DomainMessage.CreateResponse(
            context.DomainMessage,
            DomainResourceRecords.Empty,
            DomainResponseCode.NameError);
        completions[0].TrySetResult(response);

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
        var contexts = new List<DomainMessageContext>();
        var completions = new List<TaskCompletionSource<DomainMessage?>>();
        var pipeline = HeldPipeline(contexts, completions);
        var executor = CreateExecutor(pipeline);
        var request = DomainMessage.CreateRequest("health.example");

        var queryTask = executor.QueryAsync(request, CancellationToken.None).AsTask();

        var context = Assert.Single(contexts);
        Assert.Equal("health.example", context.DomainMessage.Questions[0].Name.ToString());
        Assert.True(context.BypassCache);
        Assert.True(context.DoNotCacheResponse);

        var response = DomainMessage.CreateResponse(
            context.DomainMessage,
            DomainResourceRecords.Empty,
            DomainResponseCode.NoError);
        completions[0].TrySetResult(response);

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
