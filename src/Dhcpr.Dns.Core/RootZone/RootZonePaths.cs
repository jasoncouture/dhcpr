using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.RootZone;

public static class RootZonePaths
{
    public const string RootZoneFileName = "root.zone";
    public const string RootZoneUrl = "https://www.internic.net/domain/root.zone";

    public static readonly string[] NamedRootUrls =
    [
        "https://www.internic.net/domain/named.root",
        "https://192.0.46.9/domain/named.root",
        "http://192.0.46.9/domain/named.root"
    ];

    public static string GetDirectory(IOptionsMonitor<RootServerConfiguration> options)
    {
        var cacheFile = options.CurrentValue.CacheFilePath;
        if (string.IsNullOrWhiteSpace(cacheFile))
            return ".";
        var dir = Path.GetDirectoryName(Path.GetFullPath(cacheFile));
        return string.IsNullOrEmpty(dir) ? "." : dir;
    }

    public static string GetRootZonePath(IOptionsMonitor<RootServerConfiguration> options)
        => Path.Combine(GetDirectory(options), RootZoneFileName);

    public static string GetNamedRootCachePath(IOptionsMonitor<RootServerConfiguration> options)
    {
        var configured = options.CurrentValue.CacheFilePath;
        return string.IsNullOrWhiteSpace(configured) ? "root-servers.txt" : configured;
    }
}
