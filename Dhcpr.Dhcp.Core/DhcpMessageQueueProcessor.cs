using System.Buffers;
using System.Net;
using System.Net.Sockets;

using Dhcpr.Core.Queue;
using Dhcpr.Dhcp.Core.Pipeline;
using Dhcpr.Dhcp.Core.Protocol;

using Microsoft.Extensions.Logging;

namespace Dhcpr.Dhcp.Core;

public sealed class DhcpMessageQueueProcessor : IQueueMessageProcessor<QueuedDhcpMessage>
{
    private readonly IEnumerable<IDhcpRequestHandler> _handlers;
    private readonly ILogger<DhcpMessageQueueProcessor> _logger;

    public DhcpMessageQueueProcessor(IEnumerable<IDhcpRequestHandler> handlers,
        ILogger<DhcpMessageQueueProcessor> logger)
    {
        _handlers = handlers.OrderByDescending(i => i.Priority)
            .ThenBy(i => i.Name)
            .ToArray();
        _logger = logger;
    }

    public async Task ProcessMessageAsync(QueuedDhcpMessage message, CancellationToken cancellationToken)
    {
        var (udpClient, requestContext) = message;
        try
        {
            using (_logger.BeginScope("{macAddress}", requestContext.Message.HardwareAddress))
            using (_logger.BeginScope("{network}", requestContext.NetworkInformation))
            {
                _logger.LogInformation("Processing DHCP message, network information {network}",
                    requestContext.NetworkInformation);
                foreach (var handler in _handlers)
                {
                    try
                    {
                        await handler.HandleDhcpRequest(requestContext, cancellationToken);
                        if (!requestContext.Cancel)
                            continue;

                        _logger.LogInformation("DHCP Handler {name} cancelled further processing",
                            handler.Name);
                        break;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex,
                            "DHCP Handler {name} threw an exception, cancelling further processing",
                            handler.Name);
                        return;
                    }
                }

                await EncodeAndSendAsync(requestContext, udpClient, cancellationToken);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested) { }
        catch (Exception ex)
        {
            _logger.LogWarning(ex,
                "Something went wrong when processing a DHCP message for {macAddress}, here's the network information: {networkInfo}",
                requestContext.Message.HardwareAddress, requestContext.NetworkInformation);
        }
    }

    private async Task EncodeAndSendAsync(DhcpRequestContext requestContext, UdpClient udpClient,
        CancellationToken cancellationToken)
    {
        if (requestContext.Response is null)
        {
            return;
        }

        if (requestContext.Response.Options.Length > 0 &&
            requestContext.Response.Options.Last().Code != DhcpOptionCode.End)
        {
            requestContext.Response = requestContext.Response with
            {
                Options = new DhcpOptionCollection(requestContext.Response.Options.Append(DhcpOption.End))
            };
        }

        var targetEndPoint = new IPEndPoint(requestContext.NetworkInformation.Network.BroadcastAddress,
            Constants.DhcpClientPort);
        if (!requestContext.Message.ClientAddress.Equals(IPAddress.Any) &&
            !requestContext.Message.Flags.HasFlag(DhcpFlags.Broadcast))
        {
            targetEndPoint = new IPEndPoint(requestContext.Message.ClientAddress, Constants.DhcpClientPort);
        }


        var outboundBuffer = ArrayPool<byte>.Shared.Rent(requestContext.Response.Size);
        try
        {
            outboundBuffer.Initialize();
            requestContext.Response.EncodeTo(outboundBuffer);
            await udpClient.SendAsync(
                outboundBuffer
                    .AsMemory(0, requestContext.Response.Size),
                targetEndPoint,
                cancellationToken
            );
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(outboundBuffer);
        }
    }
}