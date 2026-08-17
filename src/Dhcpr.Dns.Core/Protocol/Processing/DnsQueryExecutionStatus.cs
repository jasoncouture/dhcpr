namespace Dhcpr.Dns.Core.Protocol.Processing;

public enum DnsQueryExecutionStatus
{
    Success,
    EmptyRequest,
    RequestTooLarge,
    InvalidWireFormat,
    NoResponse,
    Cancelled
}
