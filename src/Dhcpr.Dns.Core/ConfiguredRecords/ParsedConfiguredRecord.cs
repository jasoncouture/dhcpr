using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.ConfiguredRecords;

public sealed record ParsedConfiguredRecord(
    string Owner,
    DomainLabels Name,
    DomainRecordType Type,
    TimeSpan TimeToLive,
    IDomainResourceRecordData Data,
    ClientAccessList Clients,
    bool IsWildcard,
    string WildcardParent);
