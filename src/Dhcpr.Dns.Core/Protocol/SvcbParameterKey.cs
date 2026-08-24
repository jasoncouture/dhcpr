namespace Dhcpr.Dns.Core.Protocol;

/// <summary>RFC 9460 / 9461 SvcParamKey values.</summary>
public enum SvcbParameterKey : ushort
{
    Mandatory = 0,
    Alpn = 1,
    NoDefaultAlpn = 2,
    Port = 3,
    Ipv4Hint = 4,
    Ech = 5,
    Ipv6Hint = 6,
    DohPath = 7,
}
