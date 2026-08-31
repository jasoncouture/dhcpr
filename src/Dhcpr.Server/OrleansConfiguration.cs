using System.Diagnostics.CodeAnalysis;
using System.Net;

using Dhcpr.Core;

namespace Dhcpr.Server;

public sealed class OrleansConfiguration : IValidateSelf
{
    public const int DefaultSiloPort = 11111;
    public const int DefaultGatewayPort = 30000;

    public bool UseConsul { get; set; }

    public ConsulClusteringConfiguration Consul { get; set; } = new();

    public string AdvertisedIP { get; set; } = "";

    public int SiloPort { get; set; } = DefaultSiloPort;

    public int GatewayPort { get; set; } = DefaultGatewayPort;

    public bool Validate() => TryValidate(out _);

    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract",
        Justification = "Values are set by configuration binding")]
    public bool TryValidate([NotNullWhen(false)] out string? error)
    {
        Consul ??= new ConsulClusteringConfiguration();
        Consul.Address ??= "";
        Consul.Token ??= "";
        Consul.KvRootFolder ??= "";
        AdvertisedIP ??= "";

        if (!UseConsul)
        {
            error = null;
            return true;
        }

        if (!Uri.TryCreate(Consul.Address, UriKind.Absolute, out var address) ||
            address.Scheme is not ("http" or "https"))
        {
            error = "Orleans:Consul:Address must be an absolute http or https URI when Orleans:UseConsul is true";
            return false;
        }

        if (!string.IsNullOrWhiteSpace(AdvertisedIP) && !IPAddress.TryParse(AdvertisedIP, out _))
        {
            error = "Orleans:AdvertisedIP is not a valid IP address";
            return false;
        }

        if (SiloPort is < 1 or > ushort.MaxValue)
        {
            error = "Orleans:SiloPort must be 1–65535";
            return false;
        }

        if (GatewayPort is < 1 or > ushort.MaxValue)
        {
            error = "Orleans:GatewayPort must be 1–65535";
            return false;
        }

        error = null;
        return true;
    }
}
