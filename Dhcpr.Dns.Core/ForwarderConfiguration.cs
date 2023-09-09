using System.Net;

using Dhcpr.Core;

namespace Dhcpr.Dns.Core;

public class ForwarderConfiguration : IValidateSelf
{
    public string[] Addresses { get; set; } = Array.Empty<string>();
    public bool Parallel { get; set; } = true;
    public bool Enabled { get; set; } = true;
    public IPEndPoint[] GetForwarderEndpoints() => Addresses.GetEndPoints();

    public bool Validate()
    {
        return Addresses.AreAllEndPointsValid();
    }
}