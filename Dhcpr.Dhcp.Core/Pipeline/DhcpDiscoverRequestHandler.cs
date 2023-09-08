using System.Net;

using Dhcpr.Dhcp.Core.Client;
using Dhcpr.Dhcp.Core.Protocol;

using Microsoft.Extensions.Logging;

namespace Dhcpr.Dhcp.Core.Pipeline;

public class DhcpDiscoverRequestHandler : IDhcpRequestHandler
{
    private readonly IDhcpLeasePool _leasePool;
    private readonly ILogger<DhcpDiscoverRequestHandler> _logger;

    public DhcpDiscoverRequestHandler(IDhcpLeasePool leasePool, ILogger<DhcpDiscoverRequestHandler> logger)
    {
        _leasePool = leasePool;
        _logger = logger;
    }

    public ValueTask HandleDhcpRequest(DhcpRequestContext context, CancellationToken cancellationToken)
    {
        if (context.Response is not null) return ValueTask.CompletedTask;
        var dhcpMessageTypeOption = context.Message.Options.GetOptionForCode(DhcpOptionCode.DhcpMessageType);
        var dhcpMessageType = (DhcpMessageType)dhcpMessageTypeOption!.Payload[0];
        if (dhcpMessageType != DhcpMessageType.Discover) return ValueTask.CompletedTask;
        if (!_leasePool.TryGetDhcpLease(context.Message.HardwareAddress, out var lease) ||
            lease.Network != context.NetworkInformation.Network)
        {
            lease = _leasePool.TryCreateLease(context.Message.HardwareAddress, context.NetworkInformation.Network);
        }

        if (lease is null)
        {
            context.Cancel = true;
            _logger.LogInformation("Could not create initial DHCP lease for {address}",
                context.Message.HardwareAddress);
            return ValueTask.CompletedTask;
        }

        lease = lease with
        {
            State = DhcpClientState.Offered,
            Gateway = IPAddress.Any, //context.NetworkInformation.Network.Address,
            TransactionId = context.Message.TransactionId,
            DomainName = "localdomain",
            Created = DateTimeOffset.Now,
            MessageTemplate = DhcpMessage.Template
        };

        if (!_leasePool.TrySetLease(lease))
        {
            _logger.LogWarning("Failed to update DHCP lease state, cancelling further processing");
            context.Cancel = true;
            return ValueTask.CompletedTask;
        }

        var messageTemplate = lease.ToDhcpMessageTemplate(DhcpMessageType.Offer, context.Message);

        context.Response = messageTemplate;

        return ValueTask.CompletedTask;
    }
}