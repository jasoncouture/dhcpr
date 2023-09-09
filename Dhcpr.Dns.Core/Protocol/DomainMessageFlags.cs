namespace Dhcpr.Dns.Core.Protocol;

public record DomainMessageFlags(
    ushort Id,
    bool Response,
    DomainOperationCode Operation,
    bool Authorative,
    bool Truncated,
    bool RecursionDesired,
    bool RecursionAvailable,
    bool Authentic,
    bool CheckingDisabled,
    DomainResponseCode ResponseCode
) : ISelfComputeSize
{
    public int Size => 4;
}