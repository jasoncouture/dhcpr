namespace Dhcpr.Dns.Core.Protocol;

public enum DomainOperationCode : byte
{
    Query = 0,
    IQuery = 1,
    Status = 2,
    Notify = 4,
    Update = 5,
}