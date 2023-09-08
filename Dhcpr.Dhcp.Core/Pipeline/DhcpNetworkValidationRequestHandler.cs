using System.Net;

using Dhcpr.Core;
using Dhcpr.Dhcp.Core.Client;

using Microsoft.Extensions.Logging;

namespace Dhcpr.Dhcp.Core.Pipeline;

public class DhcpNetworkValidationRequestHandler : IDhcpRequestHandler
{
    private readonly ILogger<DhcpNetworkValidationRequestHandler> _logger;
    private readonly IPNetwork[] _networks;
    public int Priority => 500;

    public DhcpNetworkValidationRequestHandler(ILogger<DhcpNetworkValidationRequestHandler> logger,
        IEnumerable<IDhcpSubnet> subnets)
    {
        _logger = logger;
        // TODO: Get this from config, and keep it up to date.
        _networks = new[]
        {
            new IPNetwork(IPAddress.Parse("10.0.0.0"), IPAddress.Parse("10.0.0.255"), IPAddress.Parse("10.0.0.255"))
        };
    }

    public ValueTask HandleDhcpRequest(DhcpRequestContext context, CancellationToken cancellationToken)
    {
        var isValidNetwork =
            _networks.Any(
                i => context.NetworkInformation.Network.Address.IsInNetwork(i.Address,
                    context.NetworkInformation.Network.NetworkMask)
            );

        context.Cancel = !isValidNetwork;
        if (context.Cancel)
        {
            _logger.LogInformation(
                "Ignoring DHCP request from {clientHardwareAddress} on network {address} because it is not configured as a DHCP interface",
                context.Message.HardwareAddress,
                context.NetworkInformation.Network.Address
            );
        }

        return ValueTask.CompletedTask;
    }
}