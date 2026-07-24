using System.Diagnostics.CodeAnalysis;

namespace Dhcpr.Dns.Core.Protocol;

[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum DomainRecordType : ushort
{
    A = 0x1,
    NS = 0x2,
    CNAME = 0x5,
    SOA = 0x6,
    WKS = 0x0B,
    PTR = 0x0C,
    HINFO = 0x0D,
    MX = 0x0F,
    TXT = 0x10,
    AAAA = 0x1C,
    SRV = 0x21,
    OPT = 0x29,
    DS = 0x2B,
    RRSIG = 0x2E,
    NSEC = 0x2F,
    DNSKEY = 0x30,
    NSEC3 = 0x32,
    NSEC3PARAM = 0x33,
    SVCB = 0x40,
    HTTPS = 0x41,
}