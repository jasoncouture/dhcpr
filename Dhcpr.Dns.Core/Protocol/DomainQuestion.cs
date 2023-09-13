namespace Dhcpr.Dns.Core.Protocol;

public record DomainQuestion(DomainLabels Name, DomainRecordType Type, DomainRecordClass Class) : ISelfComputeEstimatedSize
{
    private int? _size;
    public int EstimatedSize => _size ??= Name.EstimatedSize + sizeof(DomainRecordType) + sizeof(DomainRecordClass);
}