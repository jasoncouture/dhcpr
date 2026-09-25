using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;

using Dhcpr.Core;
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
    public async Task DoesNotDisposeTcpClientUntilProcessAndSendFinishes()
    {
        var directory = Directory.CreateTempSubdirectory();
        try
        {
            var (certificatePath, keyPath) = TlsCertificateFiles.WritePemPair(directory.FullName, "localhost");
            var tls = ValidTls(certificatePath, keyPath);

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
            var certificates = new FileTlsServerCertificateProvider(Monitor(tls));
            certificates.Refresh();
            var server = new DnsServer(
                pipeline,
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

                server.HandleTlsClientAsync(accepted, CancellationToken.None);
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

                var context = await started.Task.WaitAsync(TimeSpan.FromSeconds(5));
                Assert.Equal(DnsQuerySource.Dot, context.Source);

                Assert.False(IsDisposed(accepted));

                release.TrySetResult(null);
                await WaitUntilDisposed(accepted, TimeSpan.FromSeconds(5));
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

    [Fact]
    public async Task TlsHandshakeTimeoutDisposesClient()
    {
        var directory = Directory.CreateTempSubdirectory();
        try
        {
            var (certificatePath, keyPath) = TlsCertificateFiles.WritePemPair(directory.FullName, "localhost");
            var tls = ValidTls(certificatePath, keyPath);
            var certificates = new FileTlsServerCertificateProvider(Monitor(tls));
            certificates.Refresh();
            var server = new DnsServer(
                Substitute.For<IDnsQueryPipeline>(),
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

                server.HandleTlsClientAsync(accepted, CancellationToken.None);
                await WaitUntilDisposed(accepted, DnsServer.TcpReadTimeout + TimeSpan.FromSeconds(2));
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

    private static TlsConfiguration ValidTls(string certificatePath, string keyPath)
    {
        var tls = new TlsConfiguration
        {
            Enabled = true,
            Listeners = ["127.0.0.1:853"],
            CertificatePath = certificatePath,
            PrivateKeyPath = keyPath
        };
        Assert.True(tls.TryValidate(out _));
        return tls;
    }

    private static async Task WaitUntilDisposed(TcpClient client, TimeSpan timeout)
    {
        var deadline = DateTime.UtcNow + timeout;
        while (!IsDisposed(client) && DateTime.UtcNow < deadline)
            await Task.Delay(10);
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
