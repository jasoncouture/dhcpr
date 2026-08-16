using System.Net;
using System.Net.Sockets;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.UnitTests;

public class DomainClientDisposeTests
{
    [Fact]
    public void UdpDomainClientDisposeClosesSocket()
    {
        var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Client.Bind(new IPEndPoint(IPAddress.Any, 0));
        var client = new UdpDomainClient(udp, new IPEndPoint(IPAddress.Loopback, 53));

        client.Dispose();

        Assert.Null(udp.Client);
    }

    [Fact]
    public void TimeoutWrapperDisposeClosesInner()
    {
        var inner = new DisposableClient();
        var wrapper = new DomainClientTimeoutWrapper(inner, TimeSpan.FromSeconds(1));

        wrapper.Dispose();

        Assert.True(inner.Disposed);
    }

    [Fact]
    public void TimeoutWrapperDisposeClosesUdpSocket()
    {
        var udp = new UdpClient(AddressFamily.InterNetwork);
        udp.Client.Bind(new IPEndPoint(IPAddress.Any, 0));
        var inner = new UdpDomainClient(udp, new IPEndPoint(IPAddress.Loopback, 53));
        var wrapper = new DomainClientTimeoutWrapper(inner, TimeSpan.FromSeconds(1));

        wrapper.Dispose();

        Assert.Null(udp.Client);
    }

    private sealed class DisposableClient : IDomainClient
    {
        public bool Disposed { get; private set; }

        public ValueTask<DomainMessage> SendAsync(DomainMessage message, CancellationToken cancellationToken)
            => ValueTask.FromResult(DomainMessage.CreateResponse(message));

        public void Dispose() => Disposed = true;
    }
}
