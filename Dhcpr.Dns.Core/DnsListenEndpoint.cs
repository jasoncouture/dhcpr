namespace Dhcpr.Dns.Core;

/// <summary>
/// A configured DNS listen target before host / interface resolution.
/// <list type="bullet">
/// <item><c>udp://127.0.0.1:53</c> / <c>tcp://localhost:53</c> — single protocol, host or IP</item>
/// <item><c>interface://enp2s0:53/</c> — every unicast address on that NIC, UDP and TCP</item>
/// </list>
/// </summary>
public readonly record struct DnsListenEndpoint(
    DnsListenProtocol Protocol,
    string Host,
    int Port,
    bool IsNetworkInterface = false);
