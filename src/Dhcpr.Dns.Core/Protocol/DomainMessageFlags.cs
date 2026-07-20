namespace Dhcpr.Dns.Core.Protocol;

public record DomainMessageFlags(
    bool Response,
    DomainOperationCode Operation,
    bool Authorative,
    bool Truncated,
    bool RecursionDesired,
    bool RecursionAvailable,
    bool Authentic,
    bool CheckingDisabled,
    DomainResponseCode ResponseCode
) : ISelfComputeEstimatedSize
{
    public int EstimatedSize => 2;
}