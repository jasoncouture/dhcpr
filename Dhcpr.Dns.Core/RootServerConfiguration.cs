using System.Diagnostics.CodeAnalysis;

using Dhcpr.Core;

namespace Dhcpr.Dns.Core;

public class RootServerConfiguration : IValidateSelf
{
    public string CacheFilePath { get; set; } = "root-servers.txt";
    public bool Download { get; set; } = true;
    public bool LoadFromSystem { get; set; } = true;
    public string[] Addresses { get; set; } = Array.Empty<string>();

    public Uri[] DownloadUrls { get; set; } =
    {
        new Uri("https://www.internic.net/domain/named.root"),
        new Uri("https://192.0.46.9/domain/named.root"),
        new Uri("http://192.0.46.9/domain/named.root")
    };

    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract",
        Justification = "Values are set by reflection")]
    public bool Validate()
    {
        if (CacheFilePath is null) return false;
        if (Addresses is null) return false;
        if (DownloadUrls is null) return false;
        if (DownloadUrls.Any(i => i is null || !i.IsAbsoluteUri)) return false;
        if (Addresses.Any(i => i is null)) return false;
        return Addresses.All(i => i.IsValidIPAddress());
    }
}