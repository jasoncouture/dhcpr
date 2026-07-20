namespace Dhcpr.Dns.Core;

public enum DnsListenProtocol
{
    Udp,
    Tcp,

    /// <summary>
    /// Bind both UDP and TCP (used by <c>interface://</c> listen URIs).
    /// </summary>
    Both
}
