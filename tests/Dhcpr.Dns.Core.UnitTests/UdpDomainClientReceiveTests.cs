using System.Net;
using System.Net.Sockets;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Parser;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.UnitTests;

public class UdpDomainClientReceiveTests
{
    [Fact]
    public async Task IgnoresWrongSourceAndDoesNotShrinkReceiveBuffer()
    {
        using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        var serverEp = (IPEndPoint)server.Client.LocalEndPoint!;

        using var attacker = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));

        using var clientUdp = new UdpClient(AddressFamily.InterNetwork);
        clientUdp.Client.Bind(new IPEndPoint(IPAddress.Loopback, 0));
        using var client = new UdpDomainClient(clientUdp, serverEp);

        var request = DomainMessage.CreateRequest("example.com");
        var spoofed = DomainMessage.CreateResponse(
            request,
            answers: [A("example.com", "1.2.3.4")],
            responseCode: DomainResponseCode.NoError);
        var real = DomainMessage.CreateResponse(
            request,
            answers: [A("example.com", "9.9.9.9")],
            responseCode: DomainResponseCode.NoError);
        var tinyWrongId = request with { Id = unchecked((ushort)(request.Id + 1)) };

        var serverTask = Task.Run(async () =>
        {
            var incoming = await server.ReceiveAsync();
            await SendEncodedAsync(attacker, spoofed, incoming.RemoteEndPoint);
            await SendEncodedAsync(server, tinyWrongId, incoming.RemoteEndPoint);
            await SendEncodedAsync(server, real, incoming.RemoteEndPoint);
        });

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        var result = await client.SendAsync(request, cts.Token);
        await serverTask;

        var answer = Assert.Single(result.Records.Answers);
        Assert.Equal(IPAddress.Parse("9.9.9.9"), ((IPAddressData)answer.Data).Address);
    }

    private static DomainResourceRecord A(string owner, string address)
        => new(new DomainLabels(owner), DomainRecordType.A, DomainRecordClass.IN, TimeSpan.FromSeconds(60),
            new IPAddressData(IPAddress.Parse(address)));

    private static async Task SendEncodedAsync(UdpClient from, DomainMessage message, IPEndPoint to)
    {
        var buffer = new byte[512];
        var length = DomainMessageEncoder.Encode(buffer, message);
        await from.SendAsync(buffer.AsMemory(0, length), to);
    }
}
