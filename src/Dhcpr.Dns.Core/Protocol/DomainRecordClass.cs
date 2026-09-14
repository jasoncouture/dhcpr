namespace Dhcpr.Dns.Core.Protocol;

public enum DomainRecordClass : ushort
{
    IN = 0x01,
    CH = 0x03,
    Any = 0xff
}