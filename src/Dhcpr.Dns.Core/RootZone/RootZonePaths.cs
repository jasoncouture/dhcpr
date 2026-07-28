using Microsoft.Extensions.Options;

using Dhcpr.Core;

namespace Dhcpr.Dns.Core.RootZone;

public static class RootZonePaths
{
    public const string RootZoneFileName = "root.zone";
    public const string NamedRootFileName = "root-servers.txt";
    public const string RootZoneUrl = "https://www.internic.net/domain/root.zone";

    public static readonly string[] NamedRootUrls =
    [
        "https://www.internic.net/domain/named.root",
        "https://192.0.46.9/domain/named.root",
        "http://192.0.46.9/domain/named.root"
    ];

    public static string GetDirectory(IOptionsMonitor<ApplicationConfiguration> options)
    {
        var path = options.CurrentValue.DataPath;
        if (string.IsNullOrWhiteSpace(path))
            return Path.GetFullPath(".");
        return Path.GetFullPath(path);
    }

    public static string GetRootZonePath(IOptionsMonitor<ApplicationConfiguration> options)
        => Path.Combine(GetDirectory(options), RootZoneFileName);

    public static string GetNamedRootCachePath(IOptionsMonitor<ApplicationConfiguration> options)
        => Path.Combine(GetDirectory(options), NamedRootFileName);

    public static string GetZoneFilePath(IOptionsMonitor<ApplicationConfiguration> options, string fileName)
        => Path.Combine(GetDirectory(options), fileName);
}
