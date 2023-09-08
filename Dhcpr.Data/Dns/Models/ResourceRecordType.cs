namespace Dhcpr.Data.Dns.Models;

public enum ResourceRecordType
{
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,

    //WKS = 11, // 0x0000000B - I don't know what this is yet, so it's not supported, for now.
    PTR = 12, // 0x0000000C
    MX = 15, // 0x0000000F
    TXT = 16, // 0x00000010
    AAAA = 28, // 0x0000001C
    SRV = 33, // 0x00000021
    // OPT = 41, // 0x00000029 - Same here.
}