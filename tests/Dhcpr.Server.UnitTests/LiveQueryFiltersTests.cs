using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Server.LiveQueries;
using Dhcpr.Server.Orleans.LiveQueries;

namespace Dhcpr.Server.UnitTests;

public sealed class LiveQueryFiltersTests
{
    [Theory]
    [InlineData("127.0.0.1", 0, true)]
    [InlineData("::1", 0, true)]
    [InlineData("127.0.0.1", 43767, false)]
    [InlineData("203.0.113.10", 0, false)]
    [InlineData("203.0.113.10", 53000, false)]
    public void ClassifiesHealthCheckProbes(string address, int port, bool expected)
    {
        var client = new IPEndPoint(IPAddress.Parse(address), port);
        Assert.Equal(expected, LiveQueryFilters.IsHealthCheckProbe(client));
        Assert.Equal(expected, LiveQueryFilters.IsHealthCheckProbe(CreateEvent(client)));
        Assert.Equal(expected, LiveQueryFilters.IsHealthCheckProbe(DnsQueryEventMessage.From(CreateEvent(client))));
    }

    [Fact]
    public void NullAndUnparseableClientsAreNotProbes()
    {
        Assert.False(LiveQueryFilters.IsHealthCheckProbe((IPEndPoint?)null));
        Assert.False(LiveQueryFilters.IsHealthCheckProbe(new DnsQueryEventMessage { Client = null }));
        Assert.False(LiveQueryFilters.IsHealthCheckProbe(new DnsQueryEventMessage { Client = "not-an-endpoint" }));
    }

    private static DnsQueryEvent CreateEvent(IPEndPoint client)
        => new(
            Guid.CreateVersion7(),
            DateTimeOffset.UtcNow,
            client,
            new IPEndPoint(IPAddress.Loopback, 53),
            "example.com",
            DomainRecordType.A,
            DomainResponseCode.NoError,
            CacheHit: false,
            Answers: "127.0.0.1",
            Middleware: "Test");
}
