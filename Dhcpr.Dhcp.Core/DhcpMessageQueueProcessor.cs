using System.Buffers;
using System.Net;
using System.Net.Sockets;

using Dhcpr.Core.Queue;
using Dhcpr.Dhcp.Core.Pipeline;
using Dhcpr.Dhcp.Core.Protocol;

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Dhcpr.Dhcp.Core;

public class DhcpMessageQueueProcessor : BackgroundService
{
    private readonly IMessageQueue<QueuedDhcpMessage> _requestContextQueue;
    private readonly ILogger<DhcpMessageQueueProcessor> _logger;
    private readonly IEnumerable<IDhcpRequestHandler> _handlers;

    public DhcpMessageQueueProcessor(
        IMessageQueue<QueuedDhcpMessage> requestContextQueue,
        IEnumerable<IDhcpRequestHandler> handlers,
        ILogger<DhcpMessageQueueProcessor> logger
    )
    {
        _requestContextQueue = requestContextQueue;
        _logger = logger;
        _handlers = handlers.OrderByDescending(i => i.Priority)
            .ThenBy(i => i.Name)
            .ToArray();
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                var contextMessage = await _requestContextQueue.DequeueAsync(stoppingToken);
                var context = contextMessage.Item.Context;
                var socket = contextMessage.Item.Socket;
                var cancellation = contextMessage.CancellationToken;
                using var cancellationTokenSource =
                    CancellationTokenSource.CreateLinkedTokenSource(cancellation, stoppingToken);
                await ProcessDhcpContextAsync(context, socket, cancellationTokenSource.Token);

                if (cancellationTokenSource.IsCancellationRequested) return;
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
            // Ignored, but this should never be hit.
        }
    }

    private async Task ProcessDhcpContextAsync(DhcpRequestContext requestContext, UdpClient socket,
        CancellationToken cancellationToken)
    {
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

                await EncodeAndSendAsync(requestContext, socket, cancellationToken);
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

    private async Task EncodeAndSendAsync(DhcpRequestContext requestContext, UdpClient socket,
        CancellationToken cancellationToken)
    {
        if (requestContext.Response is null)
        {
            _logger.LogInformation(
                "No interceptors provided a response DHCP message, no response will be sent.");
            return;
        }

        if (requestContext.Response.Options.Length > 0 && requestContext.Response.Options.Last().Code != DhcpOptionCode.End)
        {
            requestContext.Response = requestContext.Response with
            {
                Options = new DhcpOptionCollection(requestContext.Response.Options.Append(DhcpOption.End))
            };
        }

        var targetEndPoint = new IPEndPoint(requestContext.NetworkInformation.Network.BroadcastAddress, Constants.DhcpClientPort);
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
            _logger.LogInformation("Sending DHCP Reply to {targetEndPoint}: {message}", targetEndPoint, requestContext.Response);
            await socket.SendAsync(
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