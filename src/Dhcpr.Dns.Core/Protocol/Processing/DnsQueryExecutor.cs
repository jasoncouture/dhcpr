using System.Buffers;
using System.Net;

using Dhcpr.Core.Queue;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Parser;
using Dhcpr.Dns.Core.Validation;

using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed class DnsQueryExecutor : IDnsQueryExecutor
{
    private static readonly IPEndPoint _healthCheckEndPoint = new(IPAddress.Loopback, 0);

    private readonly IMessageQueue<DnsPacketReceivedMessage> _messageQueue;
    private readonly DnsOverHttpConfiguration _dnsOverHttp;

    public DnsQueryExecutor(
        IMessageQueue<DnsPacketReceivedMessage> messageQueue,
        IOptions<DnsConfiguration> dnsConfiguration)
    {
        _messageQueue = messageQueue;
        _dnsOverHttp = dnsConfiguration.Value.DnsOverHttp ?? new DnsOverHttpConfiguration();
    }

    public async ValueTask<DnsQueryExecutionResult> ExecuteAsync(
        ReadOnlyMemory<byte> requestWire,
        IPEndPoint clientEndPoint,
        IPEndPoint serverEndPoint,
        CancellationToken cancellationToken)
    {
        if (requestWire.Length == 0)
            return DnsQueryExecutionResult.Fail(DnsQueryExecutionStatus.EmptyRequest);

        if (requestWire.Length > _dnsOverHttp.MaxRequestBytes)
            return DnsQueryExecutionResult.Fail(DnsQueryExecutionStatus.RequestTooLarge);

        DomainMessage request;
        try
        {
            request = DomainMessageEncoder.Decode(requestWire.Span);
        }
        catch
        {
            return DnsQueryExecutionResult.Fail(DnsQueryExecutionStatus.InvalidWireFormat);
        }

        var response = await QueryAsync(request, clientEndPoint, serverEndPoint, cancellationToken)
            .ConfigureAwait(false);
        if (response is null)
            return DnsQueryExecutionResult.Fail(
                cancellationToken.IsCancellationRequested
                    ? DnsQueryExecutionStatus.Cancelled
                    : DnsQueryExecutionStatus.NoResponse);

        var buffer = ArrayPool<byte>.Shared.Rent(Math.Max(512, response.EstimatedSize));
        try
        {
            var length = DomainMessageEncoder.Encode(buffer, response);
            return DnsQueryExecutionResult.Ok(buffer.AsSpan(0, length).ToArray());
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    public ValueTask<DomainMessage?> QueryAsync(DomainMessage request, CancellationToken cancellationToken)
        => QueryAsync(request, _healthCheckEndPoint, _healthCheckEndPoint, bypassCache: true, cancellationToken);

    private ValueTask<DomainMessage?> QueryAsync(
        DomainMessage request,
        IPEndPoint clientEndPoint,
        IPEndPoint serverEndPoint,
        CancellationToken cancellationToken)
        => QueryAsync(request, clientEndPoint, serverEndPoint, bypassCache: false, cancellationToken);

    private async ValueTask<DomainMessage?> QueryAsync(
        DomainMessage request,
        IPEndPoint clientEndPoint,
        IPEndPoint serverEndPoint,
        bool bypassCache,
        CancellationToken cancellationToken)
    {
        var context = new DomainMessageContext(clientEndPoint, serverEndPoint, request)
        {
            IsInternal = false,
            BypassCache = bypassCache,
            DnssecScope = new DnssecScope(),
            WorkBudget = new QueryWorkBudget()
        };

        var queued = new HttpDnsPacketReceivedMessage(context);
        await using var registration = cancellationToken.Register(
            static state =>
            {
                var tcs = (TaskCompletionSource<DomainMessage?>)state!;
                tcs.TrySetCanceled();
            },
            queued.TaskCompletionSource);

        _messageQueue.Enqueue(queued, cancellationToken);

        try
        {
            return await queued.TaskCompletionSource.Task.ConfigureAwait(false);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return null;
        }
    }
}
