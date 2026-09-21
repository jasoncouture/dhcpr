using Dhcpr.Dns.Core;
using Dhcpr.Dns.Core.Protocol.Processing;

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class DnsListenerReadinessTests
{
    [Fact]
    public void AllBoundIsFalseUntilEveryExpectedListenerIsMarked()
    {
        var readiness = new DnsListenerReadiness();
        Assert.False(readiness.AllBound);

        readiness.SetExpected(["udp://127.0.0.1:53", "tcp://127.0.0.1:53"]);
        Assert.False(readiness.AllBound);
        Assert.Equal(["udp://127.0.0.1:53", "tcp://127.0.0.1:53"], readiness.Pending);

        readiness.MarkBound("udp://127.0.0.1:53");
        Assert.False(readiness.AllBound);
        Assert.Equal(["tcp://127.0.0.1:53"], readiness.Pending);

        readiness.MarkBound("tcp://127.0.0.1:53");
        Assert.True(readiness.AllBound);
        Assert.Empty(readiness.Pending);
    }

    [Fact]
    public async Task DnsServerMarksListenersBoundAfterSocketsListen()
    {
        var port = FreeTcpPort();
        var readiness = new DnsListenerReadiness();
        var server = new DnsServer(
            Substitute.For<IDnsQueryPipeline>(),
            Monitor(new DnsConfiguration
            {
                ListenAddresses = [$"udp://127.0.0.1:{port}", $"tcp://127.0.0.1:{port}"]
            }),
            Monitor(new TlsConfiguration()),
            Substitute.For<ITlsServerCertificateProvider>(),
            NullLogger<DnsServer>.Instance,
            readiness);

        await server.StartAsync(CancellationToken.None);
        try
        {
            var deadline = DateTime.UtcNow + TimeSpan.FromSeconds(2);
            while (!readiness.AllBound && DateTime.UtcNow < deadline)
                await Task.Delay(10);

            Assert.True(readiness.AllBound);
            Assert.Empty(readiness.Pending);
        }
        finally
        {
            await server.StopAsync(CancellationToken.None);
        }
    }

    private static int FreeTcpPort()
    {
        var listener = new System.Net.Sockets.TcpListener(System.Net.IPAddress.Loopback, 0);
        listener.Start();
        var port = ((System.Net.IPEndPoint)listener.LocalEndpoint).Port;
        listener.Stop();
        return port;
    }

    private static IOptionsMonitor<T> Monitor<T>(T value)
    {
        var monitor = Substitute.For<IOptionsMonitor<T>>();
        monitor.CurrentValue.Returns(value);
        monitor.Get(Arg.Any<string?>()).Returns(value);
        return monitor;
    }
}
