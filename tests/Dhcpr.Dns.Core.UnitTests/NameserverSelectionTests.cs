using System.Net;
using System.Net.Sockets;

using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.UnitTests;

public class NameserverSelectionTests
{
    [Fact]
    public void InterleaveFamiliesAlternatesWithoutPreferringIpv4()
    {
        var v6a = new IPEndPoint(IPAddress.Parse("2001:db8::1"), 53);
        var v6b = new IPEndPoint(IPAddress.Parse("2001:db8::2"), 53);
        var v4a = new IPEndPoint(IPAddress.Parse("192.0.2.1"), 53);
        var v4b = new IPEndPoint(IPAddress.Parse("192.0.2.2"), 53);

        var v6First = NameserverSelection.InterleaveFamilies([v6a, v6b, v4a, v4b]);
        Assert.Equal(new[] { v6a, v4a, v6b, v4b }, v6First);

        var v4First = NameserverSelection.InterleaveFamilies([v4a, v4b, v6a, v6b]);
        Assert.Equal(new[] { v4a, v6a, v4b, v6b }, v4First);
    }

    [Fact]
    public void InterleaveFamiliesSingleFamilyIsUnchanged()
    {
        var v4a = new IPEndPoint(IPAddress.Parse("192.0.2.1"), 53);
        var v4b = new IPEndPoint(IPAddress.Parse("192.0.2.2"), 53);
        Assert.Equal(new[] { v4a, v4b }, NameserverSelection.InterleaveFamilies([v4a, v4b]));
    }

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
}
