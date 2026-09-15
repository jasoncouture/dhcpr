namespace Dhcpr.Dns.Core.Protocol.Processing;

public interface IDnsMetrics
{
    void RecordQuery(DomainMessageContext context, DomainMessage response);

    void RecordQuery(DomainMessageContext context, string rcode, bool error);

    void RecordDuration(DomainMessageContext context, DomainMessage? response, TimeSpan elapsed);

    void RecordUpstream(
        string transport,
        DomainMessage request,
        DomainMessage? response,
        bool cancelled,
        bool error,
        TimeSpan elapsed);
}
