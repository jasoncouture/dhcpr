using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Server.Orleans.LiveQueries;

namespace Dhcpr.Server.UnitTests;

public sealed class DnsQueryEventMessageTests
{
    [Fact]
    public void RoundTripsSource()
    {
        var evt = new DnsQueryEvent(
            Guid.CreateVersion7(),
            DateTimeOffset.UtcNow,
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 53000),
            new IPEndPoint(IPAddress.Loopback, 853),
            "example.com",
            DomainRecordType.A,
            DomainResponseCode.NoError,
            CacheHit: true,
            Answers: "93.184.216.34",
            Middleware: "Test",
            Source: DnsQuerySource.Dot);

        var restored = DnsQueryEventMessage.From(evt).ToDnsQueryEvent();

        Assert.Equal(evt.Id, restored.Id);
        Assert.Equal(evt.Name, restored.Name);
        Assert.Equal(DnsQuerySource.Dot, restored.Source);
        Assert.True(restored.CacheHit);
    }
}
