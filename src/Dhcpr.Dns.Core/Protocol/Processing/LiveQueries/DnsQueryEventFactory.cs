using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// Fire-and-forget. A full gate returns before the yield, so the response is not queued.
/// </summary>
public sealed class DnsQueryEventFactory : IDnsQueryEventFactory
{
    private readonly ILiveQueryEventPublisher _publisher;
    private readonly SemaphoreSlim _gate = new(16, 16);

    public DnsQueryEventFactory(ILiveQueryEventPublisher publisher)
    {
        _publisher = publisher;
    }

    public async void PublishAnswersAsync(
        DomainMessageContext context,
        DomainMessage response,
        string middlewareName,
        CancellationToken cancellationToken)
    {
        if (context.IsInternal)
            return;

        if (!await _gate.WaitAsync(0))
            return;

        try
        {
            await Task.Yield();

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

                await _publisher.PublishAsync(evt, cancellationToken);
            }
        }
        catch (OperationCanceledException)
        {
        }
        catch (Exception)
        {
            // The datagram is already on its way.
        }
        finally
        {
            _gate.Release();
        }
    }

    private static string FormatAnswerAddresses(DomainMessage response, DomainRecordType type) =>
        string.Join(
            ", ",
            response.Records.Answers
                .Where(r => r.Type == type && r.Data is IPAddressData)
                .Select(r => ((IPAddressData)r.Data).Address));
}
