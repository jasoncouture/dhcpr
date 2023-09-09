namespace Dhcpr.Dns.Core.Protocol;

public record DomainQuestion(DomainLabels Name, DomainRecordType Type, DomainRecordClass Class) : ISelfComputeSize
{
    private int? _size;
    public int Size => _size ??= Name.Size + sizeof(DomainRecordType) + sizeof(DomainRecordClass);
}