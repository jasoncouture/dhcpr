namespace Dhcpr.Dns.Core.Protocol;

public enum DelegationSignerDigestType : byte
{
    Sha1 = 1,
    Sha256 = 2,
    GostR3411_94 = 3,
    Sha384 = 4
}
