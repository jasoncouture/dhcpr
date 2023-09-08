using System.Diagnostics.CodeAnalysis;

using Dhcpr.Core;

namespace Dhcpr.Peering.Discovery;

public class StaticConfiguration
{
    public string[] Addresses { get; set; } = Array.Empty<string>();

    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract", Justification = "Value is set by reflection")]
    public bool Validate()
    {
        if (Addresses is null) return false;
        return Addresses.All(i => i.IsValidIPAddress());
    }
}