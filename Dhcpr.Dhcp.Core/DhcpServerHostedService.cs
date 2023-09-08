using System.Net;
using System.Net.Sockets;

using Dhcpr.Dhcp.Core.Protocol;

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Dhcpr.Dhcp.Core;

public class DhcpServerHostedService : BackgroundService
{
    private readonly ILogger<DhcpServerHostedService> _logger;

    public DhcpServerHostedService(ILogger<DhcpServerHostedService> logger)
    {
        _logger = logger;
    }

    private readonly UdpClient _dhcpServerSocket = new UdpClient();

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _dhcpServerSocket.Client.EnableBroadcast = true;
        _dhcpServerSocket.Client.Bind(new IPEndPoint(IPAddress.Any, 67));
        while (!stoppingToken.IsCancellationRequested)
        {
            var receiveResult = await _dhcpServerSocket.ReceiveAsync(stoppingToken);
            _logger.LogInformation("Got a {length} byte packet, trying to parse it as a DHCP Message",
                receiveResult.Buffer.Length);
            if (!DhcpMessage.TryParse(receiveResult.Buffer, out var dhcpMessage))
            {
                _logger.LogWarning("Unable to parse DHCP packet: {packet}",
                    string.Join(':', receiveResult.Buffer.Select(i => i.ToString("X2"))));
                return;
            }

            _logger.LogInformation("Got DHCP message from {endPoint} on {localEndPoint}: {message}",
                receiveResult.RemoteEndPoint, _dhcpServerSocket.Client.LocalEndPoint, dhcpMessage);
        }
    }
}