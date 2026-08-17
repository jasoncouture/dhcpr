using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class DnsQueryEventFactoryTests
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

        var published = new List<DnsQueryEvent>();
        var publisher = RecordingPublisher(published);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request)
        {
            CacheHit = true
        };

        await DnsQueryEventFactory.PublishAnswersAsync(
            publisher, context, response, "TestResolver", CancellationToken.None);

        Assert.Single(published);
        var evt = published[0];
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
    public async Task SkipsInternalRequests()
    {
        var request = DomainMessage.CreateRequest("example.com", DomainRecordType.A);
        var response = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        var published = new List<DnsQueryEvent>();
        var publisher = RecordingPublisher(published);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request)
        {
            IsInternal = true
        };

        await DnsQueryEventFactory.PublishAnswersAsync(
            publisher, context, response, "TestResolver", CancellationToken.None);

        Assert.Empty(published);
    }

    [Fact]
    public async Task PublishesBlackholeAnsweredByLabel()
    {
        var leaf = Substitute.For<IDomainMessageMiddleware>();
        leaf.Name.Returns("Leaf");
        var monitor = Substitute.For<Microsoft.Extensions.Options.IOptionsMonitor<DnsConfiguration>>();
        monitor.CurrentValue.Returns(new DnsConfiguration { BlackholeDomains = ["dhitc.com"] });
        var blackhole = new BlackholeDomainMiddleware(leaf, monitor);
        var published = new List<DnsQueryEvent>();
        var publisher = RecordingPublisher(published);
        var request = DomainMessage.CreateRequest("www.dhitc.com", DomainRecordType.A);
        var context = new DomainMessageContext(
            new IPEndPoint(IPAddress.Loopback, 53000),
            new IPEndPoint(IPAddress.Loopback, 53),
            request);

        var result = await blackhole.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NameError, result!.Flags.ResponseCode);
        Assert.Equal("Blackhole", context.AnsweredBy);

        await DnsQueryEventFactory.PublishAnswersAsync(
            publisher, context, result, context.AnsweredBy ?? leaf.Name, CancellationToken.None);

        Assert.Single(published);
        Assert.Equal("www.dhitc.com", published[0].Name);
        Assert.Equal(DomainResponseCode.NameError, published[0].ResponseCode);
        Assert.Equal("Blackhole", published[0].Middleware);
        await leaf.DidNotReceiveWithAnyArgs()
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    private static ILiveQueryEventPublisher RecordingPublisher(List<DnsQueryEvent> published)
    {
        var publisher = Substitute.For<ILiveQueryEventPublisher>();
        publisher.PublishAsync(Arg.Any<DnsQueryEvent>(), Arg.Any<CancellationToken>())
            .Returns(ci =>
            {
                published.Add(ci.Arg<DnsQueryEvent>());
                return ValueTask.CompletedTask;
            });
        return publisher;
    }
}
