using System.Diagnostics.CodeAnalysis;

using Dhcpr.Core;
using Dhcpr.Dns.Core.Protocol;

namespace Dhcpr.Dns.Core;

/// <summary>
/// DNSSEC validation knobs under <c>DNS:Dnssec</c>.
/// Trust anchors remain on <see cref="DnsConfiguration.TrustAnchors"/>.
/// </summary>
public sealed class DnssecConfiguration : IValidateSelf
{
    /// <summary>When false, skip validation: never set AD, never SERVFAIL for Bogus.</summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Algorithms allowed for verification. Empty means the built-in defaults
    /// (RSASHA256=8, ECDSAP256SHA256=13, ECDSAP384SHA384=14).
    /// </summary>
    public byte[] AllowedAlgorithms { get; set; } = [];

    /// <summary>Algorithms that must never be used, even if listed in AllowedAlgorithms.</summary>
    public byte[] DeniedAlgorithms { get; set; } = [];

    public static byte[] DefaultAllowedAlgorithms { get; } =
    [
        (byte)DnssecAlgorithmType.RsaSha256,
        (byte)DnssecAlgorithmType.EcdsaP256Sha256,
        (byte)DnssecAlgorithmType.EcdsaP384Sha384
    ];

    public bool IsAlgorithmAllowed(byte algorithm)
    {
        if (DeniedAlgorithms is { Length: > 0 } && DeniedAlgorithms.Contains(algorithm))
            return false;

        var allowed = AllowedAlgorithms is { Length: > 0 }
            ? AllowedAlgorithms
            : DefaultAllowedAlgorithms;

        return allowed.Contains(algorithm);
    }

    public bool Validate() => TryValidate(out _);

    public bool TryValidate([NotNullWhen(false)] out string? error)
    {
        AllowedAlgorithms ??= [];
        DeniedAlgorithms ??= [];

        foreach (var alg in AllowedAlgorithms)
        {
            if (alg == 0)
            {
                error = "DNS:Dnssec:AllowedAlgorithms must not contain 0";
                return false;
            }
        }

        foreach (var alg in DeniedAlgorithms)
        {
            if (alg == 0)
            {
                error = "DNS:Dnssec:DeniedAlgorithms must not contain 0";
                return false;
            }
        }

        error = null;
        return true;
    }
}
