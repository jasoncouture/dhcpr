using System.Net;

using Dhcpr.Dhcp.Core.Client;
using Dhcpr.Dhcp.Core.Protocol;

using Microsoft.Extensions.Logging;

namespace Dhcpr.Dhcp.Core.Pipeline;

public class DhcpSelectRequestHandler : IDhcpRequestHandler
{
    private readonly ILogger<DhcpSelectRequestHandler> _logger;
    private readonly IDhcpLeasePool _leasePool;

    public DhcpSelectRequestHandler(ILogger<DhcpSelectRequestHandler> logger, IDhcpLeasePool leasePool)
    {
        _logger = logger;
        _leasePool = leasePool;
    }
    public ValueTask HandleDhcpRequest(DhcpRequestContext context, CancellationToken cancellationToken)
    {
        if (context.Cancel) return ValueTask.CompletedTask;
        if (context.Response is not null) return ValueTask.CompletedTask;
        var dhcpMessageTypeOption = context.Message.Options.GetOptionForCode(DhcpOptionCode.DhcpMessageType);
        var dhcpMessageType = (DhcpMessageType)dhcpMessageTypeOption!.Payload[0];
        if (dhcpMessageType != DhcpMessageType.Request) return ValueTask.CompletedTask;

        if (!_leasePool.TryGetDhcpLease(context.Message.HardwareAddress, out var lease))
        {
            NegativeAcknowledge(context, "No such lease");
            return ValueTask.CompletedTask;
        }

        if (!context.NetworkInformation.Network.Contains(lease.Address))
        {
            _leasePool.TryRemoveLease(lease);
            NegativeAcknowledge(context, "Wrong network");
        }

        var addressRequestOption = context.Message.Options.GetOptionForCode(DhcpOptionCode.AddressRequest);
        if (addressRequestOption is null)
        {
            if (!context.Message.ClientAddress.Equals(IPAddress.Any))
                addressRequestOption = new DhcpOption(DhcpOptionCode.AddressRequest, context.Message.ClientAddress);
        }

        if (addressRequestOption is null || addressRequestOption.Payload.Length != 4)
        {
            NegativeAcknowledge(context, "Malformed DHCP packet");
            return ValueTask.CompletedTask;
        }

        Span<byte> addressBytes = stackalloc byte[4];
        addressRequestOption.Payload.CopyTo(addressBytes);
        var requestedAddress = new IPAddress(addressBytes);


        if (!lease.Address.Equals(requestedAddress))
        {
            _leasePool.TryRemoveLease(lease);
            NegativeAcknowledge(context, "Address conflict");
            return ValueTask.CompletedTask;
        }

        lease = lease with { State = DhcpClientState.Assigned };
        if (!_leasePool.TrySetLease(lease))
        {
            context.Cancel = true;
            _logger.LogWarning("Failed to update DHCP lease for {macAddress} to assigned. Ignoring this message", context.Message.HardwareAddress);
            return ValueTask.CompletedTask;
        }

        var message = lease.ToDhcpMessageTemplate(DhcpMessageType.Acknowledge, context.Message);
        _logger.LogInformation("Client {macAddress} has been fully assigned address: {address} ", message.HardwareAddress, message.YourAddress);
        context.Response = message;
        return ValueTask.CompletedTask;
    }

    private void NegativeAcknowledge(DhcpRequestContext context, string errorMessage)
    {
        context.Cancel = true;
        _logger.LogInformation("DHCP NAK -> {clientAddress}: {error}", context.Message.HardwareAddress, errorMessage);
        var response = context.Message with
        {
            OperationCode = BootOperationCode.Response,
            ServerAddress = IPAddress.Any,
            RelayAddress = IPAddress.Any,
            Options = new DhcpOptionCollection(new[]
            {
                new DhcpOption(DhcpOptionCode.DhcpMessageType, (byte)DhcpMessageType.NegativeAcknowledge),
                new DhcpOption(DhcpOptionCode.DhcpErrorMessage, errorMessage)
            })
        };
        context.Response = response;
    }
}