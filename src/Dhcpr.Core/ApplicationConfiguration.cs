using System.Diagnostics.CodeAnalysis;

namespace Dhcpr.Core;

public sealed class ApplicationConfiguration : IValidateSelf
{
    public const string DataProtectionKeysDirectoryName = "dataprotection-keys";
    public const string NamedRootFileName = "root-servers.txt";
    public const string RootZoneFileName = "root.zone";

    public string DataPath { get; set; } = ".";

    public string GetDataDirectory()
    {
        if (string.IsNullOrWhiteSpace(DataPath))
            return Path.GetFullPath(".");
        return Path.GetFullPath(DataPath);
    }

    public string GetDataProtectionKeysPath()
        => Path.Combine(GetDataDirectory(), DataProtectionKeysDirectoryName);

    public string GetNamedRootCachePath()
        => Path.Combine(GetDataDirectory(), NamedRootFileName);

    public string GetRootZonePath()
        => Path.Combine(GetDataDirectory(), RootZoneFileName);

    public string GetZoneFilePath(string fileName)
        => Path.Combine(GetDataDirectory(), fileName);

    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract",
        Justification = "Values are set by configuration binding")]
    public bool Validate()
        => !string.IsNullOrWhiteSpace(DataPath);
}
