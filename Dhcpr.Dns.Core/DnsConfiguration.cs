using System.Diagnostics.CodeAnalysis;
using System.Net;

using Dhcpr.Core;

namespace Dhcpr.Dns.Core;

public sealed class DnsConfiguration : IValidateSelf
{
    public RootServerConfiguration RootServers { get; set; } = new();
    public ForwarderConfiguration Forwarders { get; set; } = new();

    public IPEndPoint[] GetListenEndpoints() => ListenAddresses.GetEndPoints();
    public string[] ListenAddresses { get; set; } = { "127.0.0.1:53" };


    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract",
        Justification = "Values are set by reflection")]
    public bool Validate()
    {
        if (Forwarders is null) return false;

        return ListenAddresses.AreAllEndPointsValid() &&
               Forwarders.Validate() &&
               RootServers.Validate();
    }
}