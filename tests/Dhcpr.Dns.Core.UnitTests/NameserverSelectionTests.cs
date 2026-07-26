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
}
