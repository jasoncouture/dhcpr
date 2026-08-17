using System.Net;
using System.Net.Sockets;

using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.UnitTests;

public class NameserverSelectionTests
{
    [Fact]
    public void NetworkUnreachableIsTransportFailure()
    {
        var inner = new SocketException((int)SocketError.NetworkUnreachable);
        var wrapped = new InvalidOperationException("DNS Query failed", inner);

        Assert.True(NameserverSelection.IsTransportFailure(wrapped));
        Assert.True(NameserverSelection.IsTransportFailure(inner));
    }

    [Fact]
    public void AggregateOfTransportFailuresIsTransportFailure()
    {
        var aggregate = new AggregateException(
            new SocketException((int)SocketError.NetworkUnreachable),
            new SocketException((int)SocketError.HostUnreachable));

        Assert.True(NameserverSelection.IsTransportFailure(aggregate));
    }

    [Fact]
    public void PreferIPv4KeepsRelativeOrderWithinFamily()
    {
        var v6a = new IPEndPoint(IPAddress.Parse("2001:db8::1"), 53);
        var v4a = new IPEndPoint(IPAddress.Parse("1.2.3.4"), 53);
        var v6b = new IPEndPoint(IPAddress.Parse("2001:db8::2"), 53);
        var v4b = new IPEndPoint(IPAddress.Parse("5.6.7.8"), 53);

        var ordered = NameserverSelection.PreferIPv4([v6a, v4a, v6b, v4b]).ToArray();

        Assert.Equal([v4a, v4b, v6a, v6b], ordered);
    }
}
