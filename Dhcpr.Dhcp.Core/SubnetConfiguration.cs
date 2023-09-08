using System.Diagnostics.CodeAnalysis;
using System.Net.NetworkInformation;

using Dhcpr.Core;

namespace Dhcpr.Dhcp.Core;

[SuppressMessage("ReSharper", "ClassNeverInstantiated.Global")]
public sealed class SubnetConfiguration : IValidateSelf
{
    public required string CIDR { get; set; }
    public int TimeToLiveSeconds { get; set; }
    public bool Enabled { get; set; }
    public bool Validate()
    {
        if (TimeToLiveSeconds < 300) return false;
        if (!CIDR.TryParseClasslessInterDomainRouting(out var cidrAddress, out var cidrNetmask))
            return false;
        try
        {
            var foundNetworkAddress = NetworkInterface.GetAllNetworkInterfaces()
                .Any(i =>
                    i.GetIPProperties()
                        .UnicastAddresses
                        .Any(x => x.Address.IsInNetwork(cidrAddress, cidrNetmask)
                        ));
            if (!foundNetworkAddress) return false;
        }
        catch
        {
            // Assume it's valid, and we just don't have permission.
            // We'll find out soon enough when we try to bind interfaces.
        }

        return true;
    }
}