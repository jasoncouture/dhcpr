using System.Text;

using Dhcpr.Dns.Core.Protocol.RecordData;

using MessagePipe;

namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// Publishes completed client-facing queries for the live UI via MessagePipe.
/// Uses fire-and-forget <see cref="IAsyncPublisher{T}.Publish"/> so subscribers never block DNS.
/// </summary>
public sealed class LiveQueryEventMiddleware : IDomainMessageMiddleware
{
    private readonly IDomainMessageMiddleware _inner;
    private readonly IAsyncPublisher<DnsQueryEvent> _publisher;

    public LiveQueryEventMiddleware(
        IDomainMessageMiddleware inner,
        IAsyncPublisher<DnsQueryEvent> publisher)
    {
        _inner = inner;
        _publisher = publisher;
    }

    public string Name => _inner.Name;
    public int Priority => _inner.Priority;

    public async ValueTask<DomainMessage?> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        var result = await _inner.ProcessAsync(context, cancellationToken);

        if (result is null || context.IsInternal)
            return result;

        var timestamp = DateTimeOffset.UtcNow;
        var queryId = Guid.CreateVersion7();
        foreach (var question in context.DomainMessage.Questions)
        {
            var evt = new DnsQueryEvent(
                queryId,
                timestamp,
                context.ClientEndPoint,
                context.ServerEndPoint,
                question.Name.ToString(),
                question.Type,
                result.Flags.ResponseCode,
                context.CacheHit,
                FormatAnswerAddresses(result, question.Type),
                _inner.Name);

            // Fire-and-forget: do not await PublishAsync.
            _publisher.Publish(evt);
        }

        return result;
    }

    private static string FormatAnswerAddresses(DomainMessage response, DomainRecordType type)
    {
        var builder = new StringBuilder();
        foreach (var record in response.Records.Answers)
        {
            if (record.Type != type || record.Data is not IPAddressData addressData)
                continue;

            if (builder.Length > 0)
                builder.Append(',');
            builder.Append(addressData.Address);
        }

        return builder.ToString();
    }
}
