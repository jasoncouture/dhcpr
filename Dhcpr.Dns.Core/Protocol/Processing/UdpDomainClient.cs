using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;

using Dhcpr.Core;
using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.Processing;

[Flags]
public enum DomainClientType
{
    Udp = 1,
    // Tcp = 2,
    Internal = 4
}




public readonly record struct DomainClientOptions()
{
    internal static readonly IPEndPoint DefaultEndPoint = new IPEndPoint(IPAddress.Any, 53);
    public IPEndPoint EndPoint { get; init; } = DefaultEndPoint;
    public DomainClientType Type { get; init; } = DomainClientType.Udp;
    public TimeSpan TimeOut { get; init; } = TimeSpan.FromMilliseconds(250);

    public static DomainClientOptions Default { get; } = new();
}
public interface IDomainClientFactory
{
    public ValueTask<IDomainClient> GetParallelDomainClient(IEnumerable<DomainClientOptions> options,
        CancellationToken cancellationToken = default);
    public ValueTask<IDomainClient> GetDomainClient(DomainClientOptions options, CancellationToken cancellationToken = default);
}
public sealed class DomainClientFactory : IDomainClientFactory
{
    private readonly ISocketFactory _socketFactory;
    private readonly IInternalDomainClient _internalDomainClient;

    public DomainClientFactory(ISocketFactory socketFactory, IInternalDomainClient internalDomainClient)
    {
        _socketFactory = socketFactory;
        _internalDomainClient = internalDomainClient;
    }

    public async ValueTask<IDomainClient> GetParallelDomainClient(IEnumerable<DomainClientOptions> options, CancellationToken cancellationToken = default)
    {
        var clients = await Task.WhenAll(options.Select(i => GetDomainClient(i, cancellationToken).AsTask()));
        return new DomainClientParallelWrapper(clients);
    }

    public ValueTask<IDomainClient> GetDomainClient(DomainClientOptions options, CancellationToken cancellationToken = default)
    {
        if (options.Type != DomainClientType.Internal &&
            ReferenceEquals(options.EndPoint, DomainClientOptions.DefaultEndPoint))
        {
            throw new ArgumentException("TCP and UDP clients require an IP End point", nameof(options));
        }

        using var clients = ListPool<IDomainClient>.Default.Get();

        if (options.Type.HasFlag(DomainClientType.Internal))
        {
            clients.Add(_internalDomainClient);
        }
        if (options.Type.HasFlag(DomainClientType.Udp))
        {
            clients.Add(new UdpDomainClient(_socketFactory.GetUdpClient(), options.EndPoint));
        }

        while (clients.Count > 2)
        {
            var wrappedClients = new DomainClientWrapper(clients[^1], clients[^2]);
            clients.RemoveAt(clients.Count - 1);
            clients[^1] = wrappedClients;
        }

        if (options.TimeOut > TimeSpan.Zero)
        {
            clients[0] = new DomainClientTimeoutWrapper(clients[0], options.TimeOut);
        }

        return ValueTask.FromResult(clients[0]);

    }
}

public sealed class DomainClientParallelWrapper : IDomainClient
{
    private readonly PooledList<IDomainClient> _innerClients;

    public DomainClientParallelWrapper(IEnumerable<IDomainClient> innerClients)
    {
        _innerClients = innerClients.ToPooledList();
    }

    public async ValueTask<DomainMessage> SendAsync(DomainMessage message, CancellationToken cancellationToken)
    {
        var source = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var tasks = _innerClients.Select(i => i.SendAsync(message, source.Token).AsTask()).ToPooledList();
        using var exceptions = ListPool<Exception>.Default.Get();

        while (tasks.Count > 0)
        {
            var completed = await Task.WhenAny(tasks);
            tasks.Remove(completed);
            try
            {
                var result = await completed;
                // Orphan the remaining tasks.
                foreach (var task in tasks)
                {
                    task.IgnoreExceptionsAsync().Orphan();
                }

                source.Cancel();
                return result;
            }
            catch (AggregateException ex)
            {
                foreach (var exception in ex.InnerExceptions)
                    exceptions.Add(exception);
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }
        }

        throw new AggregateException(exceptions);
    }

    public void Dispose()
    {
        foreach (var client in _innerClients)
            client.Dispose();

        _innerClients.Dispose();
    }
}

public sealed class DomainClientTimeoutWrapper : IDomainClient
{
    private readonly IDomainClient _implementation;
    private readonly TimeSpan _timeout;

    public DomainClientTimeoutWrapper(IDomainClient implementation, TimeSpan timeout)
    {
        _implementation = implementation;
        _timeout = timeout;
    }
    public async ValueTask<DomainMessage> SendAsync(DomainMessage message, CancellationToken cancellationToken)
    {
        using var source = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        source.CancelAfter(_timeout);
        return await _implementation.SendAsync(message, cancellationToken);
    }
}
public sealed class DomainClientWrapper : IDomainClient
{
    private readonly IDomainClient _left;
    private readonly IDomainClient _right;

    public DomainClientWrapper(IDomainClient left, IDomainClient right)
    {
        _left = left;
        _right = right;
    }
    public async ValueTask<DomainMessage> SendAsync(DomainMessage message, CancellationToken cancellationToken)
    {
        var exceptions = ListPool<Exception>.Default.Get();
        try
        {
            try
            {
                return await _left.SendAsync(message, cancellationToken);
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                throw;
            }
            catch (AggregateException ex)
            {
                foreach (var exception in ex.InnerExceptions)
                    exceptions.Add(exception);
            }
            catch (Exception ex)
            {
                exceptions.Add(ex);
            }

            return await _right.SendAsync(message, cancellationToken);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            throw;
        }
        catch (AggregateException ex)
        {
            foreach (var exception in ex.InnerExceptions)
                exceptions.Add(exception);
        }
        catch (Exception ex)
        {
            exceptions.Add(ex);
        }

        throw new AggregateException(exceptions);
    }
}

[SuppressMessage("ReSharper", "SuggestBaseTypeForParameter",
    Justification = "Explicit types are desired, as only IP is supported.")]
public sealed class UdpDomainClient : IDomainClient
{
    private readonly UdpClient _udpClient;
    private readonly IPEndPoint _target;

    public UdpDomainClient(UdpClient udpClient, IPEndPoint target)
    {
        _udpClient = udpClient;
        _target = target;
    }


    public async ValueTask<DomainMessage> SendAsync(DomainMessage message,
        CancellationToken cancellationToken)
    {
        var buffer = ArrayPool<byte>.Shared.Rent(16384);
        try
        {
            int length = DomainMessageEncoder.Encode(((Memory<byte>)buffer).Span, message);

            await _udpClient.Client.SendToAsync(((Memory<byte>)buffer)[..length], _target, cancellationToken);
            return await ReceiveAndDecodeAsync(_udpClient.Client, _target, (Memory<byte>)buffer, message.Id,
                static async (socket, endPoint, payload, tc) => await socket.ReceiveFromAsync(payload, endPoint, tc),
                cancellationToken);
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static async ValueTask<DomainMessage> ReceiveAndDecodeAsync(Socket socket,
        IPEndPoint target,
        Memory<byte> buffer,
        ushort messageId,
        Func<Socket, IPEndPoint, Memory<byte>, CancellationToken, ValueTask> receiveDataMethod,
        CancellationToken cancellationToken)
    {
        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();
            await receiveDataMethod.Invoke(socket, target, buffer, cancellationToken);
            var result = DomainMessageEncoder.Decode(buffer.Span);

            if (result.Id != messageId) // ID did not match, try again.
                continue;

            return result;
        }
    }
}