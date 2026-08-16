using System.Text;

using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public static class DnsQueryEventFactory
{
    /// <summary>
    /// Publishes one live-query event per question for an external answered query.
    /// Internal pipeline re-entries are skipped so glue/DNSSEC hops do not flood the UI.
    /// </summary>
    public static async ValueTask PublishAnswersAsync(
        ILiveQueryEventPublisher publisher,
        DomainMessageContext context,
        DomainMessage response,
        string middlewareName,
        CancellationToken cancellationToken)
    {
        if (context.IsInternal)
            return;

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
                response.Flags.ResponseCode,
                context.CacheHit,
                FormatAnswerAddresses(response, question.Type),
                middlewareName);

            await publisher.PublishAsync(evt, cancellationToken);
        }
    }

    private static string FormatAnswerAddresses(DomainMessage response, DomainRecordType type)
    {
        var builder = new StringBuilder();
        foreach (var record in response.Records.Answers)
        {
            if (record.Type != type || record.Data is not IPAddressData addressData)
                continue;

            if (builder.Length > 0)
                builder.Append(", ");
            builder.Append(addressData.Address);
        }

        return builder.ToString();
    }
}
