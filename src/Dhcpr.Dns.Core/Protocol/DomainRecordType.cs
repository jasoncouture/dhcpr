using System.Diagnostics.CodeAnalysis;

namespace Dhcpr.Dns.Core.Protocol;

[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum DomainRecordType : ushort
{
    A = 0x1,
    NS = 0x2,
    MD = 0x3,
    MF = 0x4,
    CNAME = 0x5,
    SOA = 0x6,
    MB = 0x7,
    MG = 0x8,
    MR = 0x9,
    NULL = 0x0A,
    WKS = 0x0B,
    PTR = 0x0C,
    HINFO = 0x0D,
    MX = 0x0F,
    TXT = 0x10,
    AAAA = 0x1C,
    SRV = 0x21,
    NAPTR = 0x23,
    DNAME = 0x27,
    OPT = 0x29,
    DS = 0x2B,
    SSHFP = 0x2C,
    RRSIG = 0x2E,
    NSEC = 0x2F,
    DNSKEY = 0x30,
    NSEC3 = 0x32,
    NSEC3PARAM = 0x33,
    TLSA = 0x34,
    SVCB = 0x40,
    HTTPS = 0x41,
    CAA = 0x101,

    /// <summary>Non-standard zone synthetic record (private-use).</summary>
    LUA = 0xFF90,

    /// <summary>Non-standard zone synthetic record (private-use).</summary>
    ALIAS = 0xFF91,
}
