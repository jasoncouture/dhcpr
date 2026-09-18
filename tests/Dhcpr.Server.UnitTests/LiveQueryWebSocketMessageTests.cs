using System.Net;
using System.Text.Json;
using System.Threading.Channels;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Server.LiveQueries;
using Dhcpr.Server.Orleans.LiveQueries;

namespace Dhcpr.Server.UnitTests;

public sealed class LiveQueryWebSocketMessageTests
{
    [Fact]
    public void SerializesQueryAndResponseAsCamelCaseJson()
    {
        var evt = DnsQueryEventMessage.From(new DnsQueryEvent(
            Guid.Parse("018f3c10-7a8b-7c9d-8e0f-102030405060"),
            new DateTimeOffset(2026, 9, 18, 16, 40, 0, TimeSpan.Zero),
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 53000),
            new IPEndPoint(IPAddress.Parse("192.0.2.53"), 53),
            "example.com",
            DomainRecordType.AAAA,
            DomainResponseCode.NoError,
            CacheHit: true,
            Answers: "2001:db8::1",
            Middleware: "Cache",
            Source: DnsQuerySource.Udp));

        var json = JsonSerializer.Serialize(
            LiveQueryWebSocketMessage.From(evt),
            LiveQueryWebSocketJsonContext.Default.LiveQueryWebSocketMessage);

        Assert.Contains("\"id\":\"018f3c10-7a8b-7c9d-8e0f-102030405060\"", json);
        Assert.Contains("\"name\":\"example.com\"", json);
        Assert.Contains("\"type\":\"AAAA\"", json);
        Assert.Contains("\"responseCode\":\"NoError\"", json);
        Assert.Contains("\"cacheHit\":true", json);
        Assert.Contains("\"answers\":\"2001:db8::1\"", json);
        Assert.Contains("\"middleware\":\"Cache\"", json);
        Assert.Contains("\"source\":\"UDP\"", json);
        Assert.Contains("\"client\":\"203.0.113.10:53000\"", json);
        Assert.Contains("\"server\":\"192.0.2.53:53\"", json);
    }

    [Fact]
    public void EnqueueSkipsHealthCheckProbes()
    {
        var channel = Channel.CreateUnbounded<DnsQueryEventMessage>();
        var probe = DnsQueryEventMessage.From(CreateEvent(new IPEndPoint(IPAddress.Loopback, 0)));
        var real = DnsQueryEventMessage.From(CreateEvent(new IPEndPoint(IPAddress.Parse("203.0.113.10"), 53000)));

        Assert.False(LiveQueryWebSocketSession.TryEnqueue(channel.Writer, probe));
        Assert.True(LiveQueryWebSocketSession.TryEnqueue(channel.Writer, real));
        Assert.True(channel.Reader.TryRead(out var received));
        Assert.Equal(real.Id, received.Id);
        Assert.False(channel.Reader.TryRead(out _));
    }

    [Fact]
    public void EnqueueDropsOldestWhenSubscriberFallsBehind()
    {
        var channel = Channel.CreateBounded<DnsQueryEventMessage>(
            new BoundedChannelOptions(LiveQueryWebSocketSession.FanOutCapacity)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = true,
                SingleWriter = false
            });

        for (var i = 0; i < LiveQueryWebSocketSession.FanOutCapacity + 50; i++)
        {
            var evt = DnsQueryEventMessage.From(CreateEvent(
                new IPEndPoint(IPAddress.Parse("203.0.113.10"), 53000 + i),
                $"q-{i}.example"));
            Assert.True(LiveQueryWebSocketSession.TryEnqueue(channel.Writer, evt));
        }

        var count = 0;
        while (channel.Reader.TryRead(out _))
            count++;

        Assert.Equal(LiveQueryWebSocketSession.FanOutCapacity, count);
    }

    private static DnsQueryEvent CreateEvent(IPEndPoint client, string name = "example.com")
        => new(
            Guid.CreateVersion7(),
            DateTimeOffset.UtcNow,
            client,
            new IPEndPoint(IPAddress.Loopback, 53),
            name,
            DomainRecordType.A,
            DomainResponseCode.NoError,
            CacheHit: false,
            Answers: "127.0.0.1",
            Middleware: "Test");
}
