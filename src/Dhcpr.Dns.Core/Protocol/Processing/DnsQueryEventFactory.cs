using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public static class DnsQueryEventFactory
{
    /// <summary>
    /// Publishes one live-query event per question for an external answered query.
    /// Fire-and-forget: the reply is not held for the publisher.
    /// Internal pipeline re-entries are skipped so glue/DNSSEC hops do not flood the UI.
    /// </summary>
    public static async void PublishAnswersAsync(
        ILiveQueryEventPublisher publisher,
        DomainMessageContext context,
        DomainMessage response,
        string middlewareName,
        CancellationToken cancellationToken)
    {
        try
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
                    middlewareName,
                    context.Source);

                await publisher.PublishAsync(evt, cancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception)
        {
            // The datagram is already on its way.
        }
    }

    private static string FormatAnswerAddresses(DomainMessage response, DomainRecordType type) =>
        string.Join(
            ", ",
            response.Records.Answers
                .Where(r => r.Type == type && r.Data is IPAddressData)
                .Select(r => ((IPAddressData)r.Data).Address));
}
