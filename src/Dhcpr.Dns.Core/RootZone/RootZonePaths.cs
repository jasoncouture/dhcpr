using Microsoft.Extensions.Options;

using Dhcpr.Core;

namespace Dhcpr.Dns.Core.RootZone;

public static class RootZonePaths
{
    public const string RootZoneFileName = ApplicationConfiguration.RootZoneFileName;
    public const string NamedRootFileName = ApplicationConfiguration.NamedRootFileName;
    public const string RootZoneUrl = "https://www.internic.net/domain/root.zone";

    public static readonly string[] NamedRootUrls =
    [
        "https://www.internic.net/domain/named.root",
        "https://192.0.46.9/domain/named.root",
        "http://192.0.46.9/domain/named.root"
    ];

    public static string GetDirectory(IOptionsMonitor<ApplicationConfiguration> options)
        => options.CurrentValue.GetDataDirectory();

    public static string GetRootZonePath(IOptionsMonitor<ApplicationConfiguration> options)
        => options.CurrentValue.GetRootZonePath();

    public static string GetNamedRootCachePath(IOptionsMonitor<ApplicationConfiguration> options)
        => options.CurrentValue.GetNamedRootCachePath();

    public static string GetZoneFilePath(IOptionsMonitor<ApplicationConfiguration> options, string fileName)
        => options.CurrentValue.GetZoneFilePath(fileName);
}
