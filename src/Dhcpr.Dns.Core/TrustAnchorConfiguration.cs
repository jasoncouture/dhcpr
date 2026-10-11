using System.Diagnostics.CodeAnalysis;
using Dhcpr.Core;

namespace Dhcpr.Dns.Core;

public sealed class TrustAnchorConfiguration : IValidateSelf
{
    /// <summary>
    /// KSK-2017. Signed the root until 2026-10-11. Still published until it is revoked.
    /// </summary>
    public const ushort Ksk2017KeyTag = 20326;

    /// <summary>KSK-2024. Signs the root DNSKEY set as of 2026-10-11.</summary>
    public const ushort Ksk2024KeyTag = 38696;

    public string Name { get; set; } = ".";
    public ushort KeyTag { get; set; } = Ksk2017KeyTag;
    public byte Algorithm { get; set; } = 8;
    public byte DigestType { get; set; } = 2;
    public string DigestHex { get; set; } = "E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D";

    /// <summary>
    /// Bootstrap anchors. RFC 5011 adopts the next KSK while one of these still signs.
    /// A key that is already the sole signer cannot be learned after the fact.
    /// </summary>
    public static TrustAnchorConfiguration[] DefaultRootAnchors() =>
    [
        new TrustAnchorConfiguration(),
        new TrustAnchorConfiguration
        {
            Name = ".",
            KeyTag = Ksk2024KeyTag,
            Algorithm = 8,
            DigestType = 2,
            DigestHex = "683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16"
        }
    ];

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
