using System.Diagnostics.CodeAnalysis;

namespace Dhcpr.Core;

public sealed class ApplicationConfiguration : IValidateSelf
{
    public const string DataProtectionKeysDirectoryName = "dataprotection-keys";
    public const string CacheDirectoryName = "cache";
    public const string ZonesDirectoryName = "zones";
    public const string DynamicDnsFileName = "dynamic-dns.json";
    public const string NamedRootFileName = "root-servers.txt";
    public const string RootZoneFileName = "root.zone";

    public string DataPath { get; set; } = ".";

    public string GetDataDirectory()
    {
        if (string.IsNullOrWhiteSpace(DataPath))
            return Path.GetFullPath(".");
        return Path.GetFullPath(DataPath);
    }

    public string GetCacheDirectory()
        => Path.Combine(GetDataDirectory(), CacheDirectoryName);

    public string GetDataProtectionKeysPath()
        => Path.Combine(GetDataDirectory(), DataProtectionKeysDirectoryName);

    public string GetNamedRootCachePath()
        => Path.Combine(GetCacheDirectory(), NamedRootFileName);

    public string GetRootZonePath()
        => Path.Combine(GetCacheDirectory(), RootZoneFileName);

    public string GetZonesDirectory()
        => Path.Combine(GetDataDirectory(), ZonesDirectoryName);

    public string GetDynamicDnsPath()
        => Path.Combine(GetDataDirectory(), DynamicDnsFileName);

    /// <summary>Path under the data directory (used by root-zone helpers).</summary>
    public string GetZoneFilePath(string fileName)
        => Path.Combine(GetDataDirectory(), fileName);

    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract",
        Justification = "Values are set by configuration binding")]
    public bool Validate()
        => !string.IsNullOrWhiteSpace(DataPath);
}
