using Dhcpr.Dhcp.Core.Protocol;

using Microsoft.Extensions.Logging;

namespace Dhcpr.Dhcp.Core.Pipeline;

public sealed class DhcpMessageTypeValidatorRequestHandler : IDhcpRequestHandler
{
    private static readonly HashSet<DhcpMessageType> ValidMessageTypes = Enum.GetValues<DhcpMessageType>().ToHashSet();
    private readonly ILogger<DhcpMessageTypeValidatorRequestHandler> _logger;

    public DhcpMessageTypeValidatorRequestHandler(ILogger<DhcpMessageTypeValidatorRequestHandler> logger)
    {
        _logger = logger;
    }

    public int Priority => -100;

    public ValueTask HandleDhcpRequest(DhcpRequestContext context, CancellationToken cancellationToken)
    {
        var dhcpMessageTypeOption = context.Message.Options.GetOptionForCode(DhcpOptionCode.DhcpMessageType);
        if (dhcpMessageTypeOption?.Payload.Length != 1)
        {
            _logger.LogWarning("DHCP Message type option length is incorrect. Cancelling further processing.");
            context.Cancel = true;
            return ValueTask.CompletedTask;
        }

        var dhcpMessageType = (DhcpMessageType)dhcpMessageTypeOption.Payload[0];

        if (!ValidMessageTypes.Contains(dhcpMessageType))
        {
            _logger.LogWarning("Unknown DHCP Message type {messageType} from {clientAddress}", dhcpMessageType,
                context.Message.HardwareAddress);
            context.Cancel = true;
        }

        return ValueTask.CompletedTask;
    }
}