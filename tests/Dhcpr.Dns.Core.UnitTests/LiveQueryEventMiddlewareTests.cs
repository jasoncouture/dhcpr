using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;

using MessagePipe;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class LiveQueryEventMiddlewareTests
{
    [Fact]
    public async Task PublishesForExternalAnswer()
    {
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.A);
        var response = DomainMessage.CreateResponse(
            request,
            new[]
            {
                new DomainResourceRecord(
                    new DomainLabels("example.com"),
                    DomainRecordType.A,
                    DomainRecordClass.IN,
                    TimeSpan.FromSeconds(60),
                    new IPAddressData(IPAddress.Parse("93.184.216.34")))
            },
            responseCode: DomainResponseCode.NoError);

        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.Name.Returns("TestResolver");
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage?>(response));

        var publisher = new RecordingPublisher();
        var middleware = new LiveQueryEventMiddleware(inner, publisher);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request)
        {
            CacheHit = true
        };

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.Same(response, result);
        Assert.Single(publisher.Published);
        var evt = publisher.Published[0];
        Assert.Equal("example.com", evt.Name);
        Assert.Equal(DomainRecordType.A, evt.Type);
        Assert.Equal(DomainResponseCode.NoError, evt.ResponseCode);
        Assert.True(evt.CacheHit);
        Assert.Equal("93.184.216.34", evt.Answers);
        Assert.Equal("TestResolver", evt.Middleware);
        Assert.Equal(context.ClientEndPoint, evt.Client);
        Assert.Equal(context.ServerEndPoint, evt.Server);
    }

    [Fact]
    public async Task SkipsNullPassThrough()
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage?>((DomainMessage?)null));

        var publisher = new RecordingPublisher();
        var middleware = new LiveQueryEventMiddleware(inner, publisher);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            DomainMessage.CreateRequest("example.com"));

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.Null(result);
        Assert.Empty(publisher.Published);
    }

    [Fact]
    public async Task SkipsInternalRequests()
    {
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.A);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);

        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(_ => new ValueTask<DomainMessage?>(response));

        var publisher = new RecordingPublisher();
        var middleware = new LiveQueryEventMiddleware(inner, publisher);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request)
        {
            IsInternal = true
        };

        await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.Empty(publisher.Published);
    }

    private sealed class RecordingPublisher : IAsyncPublisher<DnsQueryEvent>
    {
        public List<DnsQueryEvent> Published { get; } = new();

        public void Publish(DnsQueryEvent message, CancellationToken cancellationToken = default)
            => Published.Add(message);

        public ValueTask PublishAsync(DnsQueryEvent message, CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("PublishAsync must not be used for live query events.");

        public ValueTask PublishAsync(
            DnsQueryEvent message,
            AsyncPublishStrategy publishStrategy,
            CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("PublishAsync must not be used for live query events.");
    }
}
