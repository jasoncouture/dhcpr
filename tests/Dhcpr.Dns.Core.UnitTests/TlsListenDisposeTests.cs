using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;

using Dhcpr.Core;
using Dhcpr.Core.Queue;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Parser;
using Dhcpr.Dns.Core.Protocol.Processing;

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class TlsListenDisposeTests
{
    [Fact]
    public async Task DoesNotDisposeTcpClientUntilQueuedTlsReplyFinishes()
    {
        var directory = Directory.CreateTempSubdirectory();
        try
        {
            var (certificatePath, keyPath) = TlsCertificateFiles.WritePemPair(directory.FullName, "localhost");
            var tls = new TlsConfiguration
            {
                Enabled = true,
                Listeners = ["127.0.0.1:853"],
                CertificatePath = certificatePath,
                PrivateKeyPath = keyPath
            };
            Assert.True(tls.TryValidate(out _));

            ITlsServerCertificateProvider certificates = new FileTlsServerCertificateProvider(Monitor(tls));

            var queued = new TaskCompletionSource<DnsPacketReceivedMessage>(
                TaskCreationOptions.RunContinuationsAsynchronously);
            var queue = Substitute.For<IMessageQueue<DnsPacketReceivedMessage>>();
            queue.When(q => q.Enqueue(Arg.Any<DnsPacketReceivedMessage>(), Arg.Any<CancellationToken>()))
                .Do(ci => queued.TrySetResult(ci.Arg<DnsPacketReceivedMessage>()));
            var server = new DnsServer(
                queue,
                Monitor(new DnsConfiguration()),
                Monitor(tls),
                certificates,
                NullLogger<DnsServer>.Instance);

            var listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            try
            {
                using var queryClient = new TcpClient();
                var connect = queryClient.ConnectAsync(IPAddress.Loopback, ((IPEndPoint)listener.LocalEndpoint).Port);
                using var accepted = await listener.AcceptTcpClientAsync();
                await connect;

                var handleTask = server.HandleTlsClientAsync(accepted, CancellationToken.None);
                await using var ssl = new SslStream(queryClient.GetStream(), false, static (_, _, _, _) => true);
                await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                {
                    TargetHost = "localhost",
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    ApplicationProtocols = [new SslApplicationProtocol("dot")]
                }).WaitAsync(TimeSpan.FromSeconds(5));

                var request = DomainMessage.CreateRequest("example.com");
                var payload = new byte[512];
                var payloadLength = DomainMessageEncoder.Encode(payload, request);
                var framed = new byte[payloadLength + 2];
                BitConverter.TryWriteBytes(framed.AsSpan(0, 2), ((ushort)payloadLength).ToNetworkByteOrder());
                payload.AsSpan(0, payloadLength).CopyTo(framed.AsSpan(2));
                await ssl.WriteAsync(framed);
                await ssl.FlushAsync();
                queryClient.Client.Shutdown(SocketShutdown.Send);

                var item = await queued.Task.WaitAsync(TimeSpan.FromSeconds(5));
                var tcpMessage = Assert.IsType<TcpDnsPacketReceivedMessage>(item);
                Assert.Equal(DnsQuerySource.Dot, tcpMessage.Context.Source);

                Assert.False(handleTask.IsCompleted);
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
        finally
        {
            directory.Delete(recursive: true);
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
