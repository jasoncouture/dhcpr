using System.Diagnostics.CodeAnalysis;

namespace Dhcpr.Dns.Core.Protocol;

[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum DomainRecordType : ushort
{
    A = 0x1,
    NS = 0x2,
    CNAME = 0x5,
    SOA = 0x6,
    WKS = 0x0B, // 0x0000000B 
    PTR = 0x0C, // 0x0000000C
    MX = 0x0F, // 0x0000000F
    TXT = 0x10, // 0x00000010
    AAAA = 0x1C, // 0x0000001C
    SRV = 0x21, // 0x00000021
    OPT = 0x29, // 0x00000029    
}