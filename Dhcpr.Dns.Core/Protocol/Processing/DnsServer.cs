using System.Buffers;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;

using Dhcpr.Core;
using Dhcpr.Core.Queue;
using Dhcpr.Dns.Core.Protocol.Parser;

using Microsoft.Extensions.Hosting;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed class DnsServer : BackgroundService
{
    private static readonly IPEndPoint AnyEndPoint = new IPEndPoint(IPAddress.Any, 0);
    private static readonly IPEndPoint ListenEndPoint = new IPEndPoint(IPAddress.Any, 53);
    private readonly IMessageQueue<DnsPacketReceivedMessage> _messageQueue;

    public DnsServer(IMessageQueue<DnsPacketReceivedMessage> messageQueue)
    {
        _messageQueue = messageQueue;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            await ServeUdpDnsAsync(stoppingToken);
            var udpTask = ServeUdpDnsAsync(stoppingToken);
            var tcpTask = ServeTcpDnsAsync(stoppingToken);
            await Task.WhenAll(udpTask, tcpTask);
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { }
    }

    private async Task ServeUdpDnsAsync(CancellationToken cancellationToken)
    {
        const int SIO_UDP_CONNRESET = -1744830452;
        var udpClient = new UdpClient();
        udpClient.ExclusiveAddressUse = false;
        udpClient.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.ReuseAddress, true);
        udpClient.Client.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.PacketInformation, true);
        // This prevents the socket from throwing an exception about a connection forcibly closed
        if(RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            udpClient.Client.IOControl((IOControlCode)SIO_UDP_CONNRESET, new byte[] { 0, 0, 0, 0 }, null);
        udpClient.Client.Bind(new IPEndPoint(IPAddress.Loopback, 53));
        var buffer = new byte[16384];
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                var result =
                    await udpClient.Client.ReceiveMessageFromAsync(buffer.AsMemory(), AnyEndPoint, cancellationToken);

                CreateContextAndQueueForProcessing(
                    result.RemoteEndPoint,
                    networkInterface: result.PacketInformation.Interface,
                    udpClient,
                    buffer[..result.ReceivedBytes],
                    cancellationToken
                );
            }
        }
        finally
        {
            udpClient.Dispose();
        }
    }

    private async Task HandleTcpClient(TcpClient client, CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(16384);
        var bufferSegment = new ArraySegment<byte>(buffer, 0, 2);
        int length = -1;
        var cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        try
        {
            while (client.Connected && !cancellationTokenSource.IsCancellationRequested)
            {
                // To prevent DOS attacks, limit how long the connection can idle to a very short period of time.
                cancellationTokenSource.CancelAfter(TimeSpan.FromSeconds(10));
                var receivedLength = await client.Client.ReceiveAsync(bufferSegment, cancellationToken);
                if (!cancellationTokenSource.TryReset())
                {
                    cancellationTokenSource.Dispose();
                    cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
                }

                // ReSharper disable once ConvertIfStatementToSwitchStatement
                if (receivedLength < 0) return;
                if (receivedLength == 0) continue;
                var nextSegment = new ArraySegment<byte>(buffer, bufferSegment.Offset + receivedLength,
                    bufferSegment.Count - receivedLength);
                if (length < 0)
                {
                    // Grab the first 2 bytes to get the message length.
                    length = BitConverter.ToUInt16(buffer).ToHostByteOrder();
                    if (length > 16384)
                    {
                        return;
                    }

                    bufferSegment = new ArraySegment<byte>(buffer, 0, length);
                    continue;
                }

                if (bufferSegment.Count + bufferSegment.Offset < length)
                {
                    // Need more data.
                    bufferSegment = nextSegment;
                    continue;
                }

                CreateContextAndQueueForProcessing(client, buffer, cancellationToken);
                // We sized our buffer so that we only asked for the exact amount we needed.
                // So we can just reset the buffer here without any risk of losing data.
                bufferSegment = new ArraySegment<byte>(buffer, 0, 2);
                length = -1;
            }
        }
        catch
        {
            // Ignored.
        }
        finally
        {
            cancellationTokenSource.Dispose();
            ArrayPool<byte>.Shared.Return(buffer);
            client.Dispose();
        }
    }

    private void CreateContextAndQueueForProcessing(
        TcpClient tcpClient,
        byte[] buffer,
        CancellationToken cancellationToken
    )
    {
        if (tcpClient.Client.RemoteEndPoint is not IPEndPoint remoteIPEndPoint ||
            tcpClient.Client.LocalEndPoint is not IPEndPoint localEndPoint)
        {
            return;
        }
        // We don't catch exceptions here like we do with UDP
        // because we want to disconnect the client if they send something that doesn't work.

        var message = DomainMessageEncoder.Decode(buffer);
        var context = new DomainMessageContext(remoteIPEndPoint, localEndPoint, message);

        var messageToQueue = new TcpDnsPacketReceivedMessage(context, tcpClient);
        _messageQueue.Enqueue(messageToQueue, cancellationToken);
    }

    private void CreateContextAndQueueForProcessing(
        EndPoint remoteEndPoint,
        int networkInterface,
        UdpClient udpClient,
        byte[] bytes,
        CancellationToken cancellationToken
    )
    {
        if (remoteEndPoint is not IPEndPoint remoteIPEndPoint)
            return;
        try
        {
            var message = DomainMessageEncoder.Decode(bytes);
            IPAddress localAddress = GetLocalIPAddress(networkInterface, remoteIPEndPoint.AddressFamily);

            var endPoint = new IPEndPoint(localAddress, ListenEndPoint.Port);
            var context = new DomainMessageContext(remoteIPEndPoint, endPoint, message);

            var messageToQueue = new UdpDnsPacketReceivedMessage(context, udpClient);
            _messageQueue.Enqueue(messageToQueue, cancellationToken);
        }
        catch
        {
            // Ignored.
        }
    }

    private IPAddress GetLocalIPAddress(int networkInterface, AddressFamily addressFamily)
    {
        if (addressFamily is not AddressFamily.InterNetwork and not AddressFamily.InterNetworkV6)
            throw new ArgumentException("Only IPv4 and IPv6 are supported.", nameof(addressFamily));
        foreach (var ipProperties in NetworkInterface.GetAllNetworkInterfaces().Select(i => i.GetIPProperties()))
        {
            if (ipProperties.UnicastAddresses.All(i => i.Address.AddressFamily != addressFamily))
                continue;
            if (addressFamily == AddressFamily.InterNetwork)
            {
                if (ipProperties.GetIPv4Properties().Index != networkInterface)
                    continue;

                return ipProperties.UnicastAddresses.First(i => i.Address.AddressFamily == addressFamily).Address;
            }

            if (ipProperties.GetIPv6Properties().Index != networkInterface)
                continue;
            return ipProperties.UnicastAddresses.First(i => i.Address.AddressFamily == addressFamily).Address;
        }

        return IPAddress.Any;
    }

    private static async Task<TcpClient?> AcceptNextConnectionAsync(TcpListener listener,
        CancellationToken cancellationToken)
    {
        if (cancellationToken.IsCancellationRequested) return null;
        return await listener.AcceptTcpClientAsync(cancellationToken).AsTask().OperationCancelledToNull();
    }

    private async Task ServeTcpDnsAsync(CancellationToken stoppingToken)
    {
        var tcpServer = new TcpListener(IPAddress.Any, 53);
        var activeTasks = new List<Task>();
        Task<TcpClient?> acceptTask = Task.FromResult<TcpClient?>(null);
        try
        {
            tcpServer.Start(ushort.MaxValue);
            while (!stoppingToken.IsCancellationRequested)
            {
                var completedTask = await Task.WhenAny(activeTasks.Append(acceptTask));
                await completedTask;
                activeTasks.Remove(completedTask);
                if (completedTask == acceptTask)
                {
                    var client = await acceptTask;
                    if (client is not null)
                        activeTasks.Add(HandleTcpClient(client, stoppingToken));
                    if (stoppingToken.IsCancellationRequested)
                        return;
                    acceptTask = AcceptNextConnectionAsync(tcpServer, stoppingToken);
                }
            }
        }
        finally
        {
            tcpServer.Stop();
            await Task.WhenAll(activeTasks.Append(acceptTask)).IgnoreExceptionsAsync();
        }
    }
}