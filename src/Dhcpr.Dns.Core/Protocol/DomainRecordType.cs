using System.Diagnostics.CodeAnalysis;

namespace Dhcpr.Dns.Core.Protocol;

[SuppressMessage("ReSharper", "InconsistentNaming")]
public enum DomainRecordType : ushort
{
    A = 1,
    NS = 2,
    MD = 3,
    MF = 4,
    CNAME = 5,
    SOA = 6,
    MB = 7,
    MG = 8,
    MR = 9,
    NULL = 10,
    WKS = 11,
    PTR = 12,
    HINFO = 13,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    NAPTR = 35,
    DNAME = 39,
    OPT = 41,
    DS = 43,
    SSHFP = 44,
    RRSIG = 46,
    NSEC = 47,
    DNSKEY = 48,
    NSEC3 = 50,
    NSEC3PARAM = 51,
    TLSA = 52,
    SVCB = 64,
    HTTPS = 65,
    CAA = 257,

    /// <summary>Non-standard zone synthetic record (private-use).</summary>
    LUA = 65400,

    /// <summary>Non-standard zone synthetic record (private-use).</summary>
    ALIAS = 65401,
}
