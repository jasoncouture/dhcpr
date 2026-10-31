namespace Dhcpr.Dns.Core.Protocol.Processing.LiveQueries;

public interface IDnsQueryEventFactory
{
    /// <summary>
    /// Publishes one live-query event per question for an external answered query.
    /// Internal pipeline re-entries are skipped so glue/DNSSEC hops do not flood the UI.
    /// </summary>
    void PublishAnswersAsync(
        DomainMessageContext context,
        DomainMessage response,
        string middlewareName,
        CancellationToken cancellationToken);
}
