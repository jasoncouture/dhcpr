using System.Net;
using System.Net.Sockets;

using Dhcpr.Core;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Parser;
using Dhcpr.Dns.Core.Protocol.Processing;

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class TcpListenDisposeTests
{
    [Fact]
    public async Task DoesNotDisposeTcpClientUntilProcessAndSendFinishes()
    {
        var started = new TaskCompletionSource<DomainMessageContext>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<DomainMessage?>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var pipeline = Substitute.For<IDnsQueryPipeline>();
        pipeline.ExecuteAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                started.TrySetResult(call.Arg<DomainMessageContext>());
                return new ValueTask<DomainMessage?>(release.Task);
            });
        var server = new DnsServer(
            pipeline,
            Monitor(new DnsConfiguration()),
            Monitor(new TlsConfiguration()),
            Substitute.For<ITlsServerCertificateProvider>(),
            NullLogger<DnsServer>.Instance);

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            using var queryClient = new TcpClient();
            var connect = queryClient.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
            using var accepted = await listener.AcceptTcpClientAsync();
            await connect;

            var handleTask = server.HandleTcpClientAsync(accepted, CancellationToken.None);

            var request = DomainMessage.CreateRequest("example.com");
            var payload = new byte[512];
            var payloadLength = DomainMessageEncoder.Encode(payload, request);
            var framed = new byte[payloadLength + 2];
            BitConverter.TryWriteBytes(framed.AsSpan(0, 2), ((ushort)payloadLength).ToNetworkByteOrder());
            payload.AsSpan(0, payloadLength).CopyTo(framed.AsSpan(2));
            await queryClient.GetStream().WriteAsync(framed);
            queryClient.Client.Shutdown(SocketShutdown.Send);

            var context = await started.Task.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.Equal(DnsQuerySource.Tcp, context.Source);

            Assert.False(handleTask.IsCompleted);
            Assert.False(IsDisposed(accepted));

            release.TrySetResult(null);
            await handleTask.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.True(IsDisposed(accepted));
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task InFlightQueryOutlivesIdleReadTimeout()
    {
        var started = new TaskCompletionSource<DomainMessageContext>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var release = new TaskCompletionSource<DomainMessage?>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        var pipeline = Substitute.For<IDnsQueryPipeline>();
        pipeline.ExecuteAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(call =>
            {
                started.TrySetResult(call.Arg<DomainMessageContext>());
                return new ValueTask<DomainMessage?>(release.Task);
            });
        var server = new DnsServer(
            pipeline,
            Monitor(new DnsConfiguration()),
            Monitor(new TlsConfiguration()),
            Substitute.For<ITlsServerCertificateProvider>(),
            NullLogger<DnsServer>.Instance);

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            using var queryClient = new TcpClient();
            var connect = queryClient.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
            using var accepted = await listener.AcceptTcpClientAsync();
            await connect;

            var handleTask = server.HandleTcpClientAsync(accepted, CancellationToken.None);
            var request = DomainMessage.CreateRequest("example.com");
            var payload = new byte[512];
            var payloadLength = DomainMessageEncoder.Encode(payload, request);
            var framed = new byte[payloadLength + 2];
            BitConverter.TryWriteBytes(framed.AsSpan(0, 2), ((ushort)payloadLength).ToNetworkByteOrder());
            payload.AsSpan(0, payloadLength).CopyTo(framed.AsSpan(2));
            await queryClient.GetStream().WriteAsync(framed);

            await started.Task.WaitAsync(TimeSpan.FromSeconds(5));
            // Client is still waiting for the answer. The idle-read deadline
            // must not dispose the socket while that query is running.
            await Task.Delay(DnsServer.TcpReadTimeout + DnsServer.TcpReadTimeout + TimeSpan.FromMilliseconds(500));

            Assert.False(handleTask.IsCompleted);
            Assert.False(IsDisposed(accepted));

            release.TrySetResult(null);
            queryClient.Client.Shutdown(SocketShutdown.Send);
            await handleTask.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.True(IsDisposed(accepted));
        }
        finally
        {
            listener.Stop();
        }
    }

    [Fact]
    public async Task ClosesConnectionIfFullPacketNotReadWithinTimeout()
    {
        var pipeline = Substitute.For<IDnsQueryPipeline>();
        var server = new DnsServer(
            pipeline,
            Monitor(new DnsConfiguration()),
            Monitor(new TlsConfiguration()),
            Substitute.For<ITlsServerCertificateProvider>(),
            NullLogger<DnsServer>.Instance);

        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            using var queryClient = new TcpClient();
            var connect = queryClient.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
            using var accepted = await listener.AcceptTcpClientAsync();
            await connect;

            var handleTask = server.HandleTcpClientAsync(accepted, CancellationToken.None);
            // One byte of the 2-byte length prefix — not a full packet.
            await queryClient.GetStream().WriteAsync(new byte[] { 0x00 });

            await handleTask.WaitAsync(DnsServer.TcpReadTimeout + TimeSpan.FromSeconds(2));
            Assert.True(IsDisposed(accepted));
            await pipeline.DidNotReceive()
                .ExecuteAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
        }
        finally
        {
            listener.Stop();
        }
    }

    private static bool IsDisposed(TcpClient client)
    {
        try
        {
            var socket = client.Client;
            if (socket is null)
                return true;
            _ = socket.RemoteEndPoint;
            return false;
        }
        catch (ObjectDisposedException)
        {
            return true;
        }
        catch (SocketException)
        {
            return true;
        }
    }

    private static IOptionsMonitor<T> Monitor<T>(T value)
    {
        var monitor = Substitute.For<IOptionsMonitor<T>>();
        monitor.CurrentValue.Returns(value);
        monitor.Get(Arg.Any<string?>()).Returns(value);
        return monitor;
    }
}
