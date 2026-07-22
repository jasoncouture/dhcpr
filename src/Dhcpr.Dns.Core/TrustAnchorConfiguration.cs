using System.Diagnostics.CodeAnalysis;
using Dhcpr.Core;

namespace Dhcpr.Dns.Core;

public sealed class TrustAnchorConfiguration : IValidateSelf
{
    public string Name { get; set; } = ".";
    public ushort KeyTag { get; set; } = 20326;
    public byte Algorithm { get; set; } = 8;
    public byte DigestType { get; set; } = 2;
    public string DigestHex { get; set; } = "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D";

    public bool Validate() => TryValidate(out _);

    public bool TryValidate([NotNullWhen(false)] out string? error)
    {
        if (string.IsNullOrWhiteSpace(Name))
        {
            error = "Trust anchor Name must not be empty.";
            return false;
        }

        if (string.IsNullOrWhiteSpace(DigestHex))
        {
            error = "Trust anchor DigestHex must not be empty.";
            return false;
        }

        if (DigestHex.Length % 2 != 0)
        {
            error = "Trust anchor DigestHex must have an even length.";
            return false;
        }

        error = null;
        return true;
    }
}
