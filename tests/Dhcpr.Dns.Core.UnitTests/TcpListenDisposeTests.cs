using System.Net;
using System.Net.Sockets;

using Dhcpr.Core;
using Dhcpr.Core.Queue;
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
    public async Task DoesNotDisposeTcpClientUntilQueuedReplyFinishes()
    {
        var queue = new CapturingQueue();
        var server = new DnsServer(
            queue,
            Monitor(new DnsConfiguration()),
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

            var queued = await queue.WaitAsync().WaitAsync(TimeSpan.FromSeconds(5));
            Assert.IsType<TcpDnsPacketReceivedMessage>(queued);
            var tcpMessage = (TcpDnsPacketReceivedMessage)queued;

            await Task.Delay(50);
            Assert.False(IsDisposed(accepted));

            tcpMessage.SendCompleted.TrySetResult();
            await handleTask.WaitAsync(TimeSpan.FromSeconds(5));
            Assert.True(IsDisposed(accepted));
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

    private sealed class CapturingQueue : IMessageQueue<DnsPacketReceivedMessage>
    {
        private readonly TaskCompletionSource<DnsPacketReceivedMessage> _item = new(
            TaskCreationOptions.RunContinuationsAsynchronously);

        public void Enqueue(DnsPacketReceivedMessage item, CancellationToken cancellationToken)
            => _item.TrySetResult(item);

        public ValueTask<QueueItem<DnsPacketReceivedMessage>> DequeueAsync(CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public Task<DnsPacketReceivedMessage> WaitAsync() => _item.Task;
    }

    private static IOptionsMonitor<T> Monitor<T>(T value)
    {
        var monitor = Substitute.For<IOptionsMonitor<T>>();
        monitor.CurrentValue.Returns(value);
        monitor.Get(Arg.Any<string?>()).Returns(value);
        return monitor;
    }
}
