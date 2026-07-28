using System.Diagnostics.CodeAnalysis;

namespace Dhcpr.Core;

public sealed class ApplicationConfiguration : IValidateSelf
{
    public string DataPath { get; set; } = ".";

    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract",
        Justification = "Values are set by configuration binding")]
    public bool Validate()
        => !string.IsNullOrWhiteSpace(DataPath);
}
