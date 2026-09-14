namespace Dhcpr.Dns.Core.Protocol;

public enum DomainRecordClass : ushort
{
    IN = 0x01,
    CS = 0x02,
    CH = 0x03,
    HS = 0x04,
    None = 0xfe,
    Any = 0xff
}