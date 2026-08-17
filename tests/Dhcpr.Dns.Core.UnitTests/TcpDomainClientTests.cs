using System.Net;
using System.Net.Sockets;

using Dhcpr.Core;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Parser;
using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.UnitTests;

public class TcpDomainClientTests
{
    [Fact]
    public async Task RejectsResponseWithMismatchedId()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var ep = (IPEndPoint)listener.LocalEndpoint;
            var serverTask = Task.Run(async () =>
            {
                using var server = await listener.AcceptTcpClientAsync();
                var stream = server.GetStream();
                var lengthBytes = new byte[2];
                await stream.ReadExactlyAsync(lengthBytes);
                var length = BitConverter.ToUInt16(lengthBytes).ToHostByteOrder();
                var queryBuffer = new byte[length];
                await stream.ReadExactlyAsync(queryBuffer);
                var query = DomainMessageEncoder.Decode(queryBuffer);
                var wrong = DomainMessage.CreateResponse(
                    query with { Id = unchecked((ushort)(query.Id + 1)) },
                    responseCode: DomainResponseCode.NoError);
                var payload = new byte[512];
                var payloadLength = DomainMessageEncoder.Encode(payload, wrong);
                var framed = new byte[payloadLength + 2];
                BitConverter.TryWriteBytes(framed.AsSpan(0, 2), ((ushort)payloadLength).ToNetworkByteOrder());
                payload.AsSpan(0, payloadLength).CopyTo(framed.AsSpan(2));
                await stream.WriteAsync(framed);
            });

            var client = new TcpDomainClient(new SocketFactory(), ep);
            var request = DomainMessage.CreateRequest("example.com");
            using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));

            await Assert.ThrowsAsync<InvalidOperationException>(
                async () => await client.SendAsync(request, cts.Token));
            await serverTask;
        }
        finally
        {
            listener.Stop();
        }
    }
}
