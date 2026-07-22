using System.Diagnostics.CodeAnalysis;

using Dhcpr.Core;

namespace Dhcpr.Dns.Core;

public sealed class DnsConfiguration : IValidateSelf
{
    public RootServerConfiguration RootServers { get; set; } = new();
    public ForwarderConfiguration Forwarders { get; set; } = new();
    
    public TrustAnchorConfiguration[] TrustAnchors { get; set; } = { new TrustAnchorConfiguration() };

    public DnsListenEndpoint[] GetListenEndpoints() => ListenAddresses.GetListenEndpoints();

    /// <summary>
    /// Listen URIs for the DNS server.
    /// Examples: <c>udp://127.0.0.1:53</c>, <c>tcp://localhost:5353</c>,
    /// <c>interface://enp2s0:53/</c> (all addresses on that NIC, UDP+TCP).
    /// Set per environment in appsettings (e.g. Development uses 65353).
    /// </summary>
    public string[] ListenAddresses { get; set; } = Array.Empty<string>();

    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract",
        Justification = "Values are set by configuration binding")]
    public bool Validate() => TryValidate(out _);

    public bool TryValidate([NotNullWhen(false)] out string? error)
    {
        if (Forwarders is null)
        {
            error = "DNS:Forwarders is missing";
            return false;
        }

        if (ListenAddresses is null || ListenAddresses.Length == 0)
        {
            error = "DNS:ListenAddresses is missing or empty (set per environment in appsettings)";
            return false;
        }

        if (!ListenAddresses.AreAllListenAddressesValid())
        {
            error = "DNS:ListenAddresses contains an invalid listen URI";
            return false;
        }

        if (!Forwarders.Validate())
        {
            error = "DNS:Forwarders is invalid";
            return false;
        }

        if (RootServers is null || !RootServers.Validate())
        {
            error = "DNS:RootServers is invalid";
            return false;
        }

        if (TrustAnchors is not null)
        {
            foreach (var anchor in TrustAnchors)
            {
                if (!anchor.TryValidate(out error))
                {
                    error = $"DNS:TrustAnchors contains an invalid entry: {error}";
                    return false;
                }
            }
        }

        error = null;
        return true;
    }
}
