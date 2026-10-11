using System.Text.Json.Serialization;

namespace Dhcpr.Dns.Core.Validation;

/// <summary>RFC 5011 §2.3. A new SEP key must be seen continuously this long before it is trusted.</summary>
public static class Rfc5011Timing
{
    public static readonly TimeSpan AddHoldDown = TimeSpan.FromDays(30);
}

[JsonConverter(typeof(JsonStringEnumConverter))]
public enum TrustAnchorAcceptance
{
    Trusted,
    Pending
}

public enum TrustAnchorEventKind
{
    Pending,
    Trusted,
    Revoked,
    PendingDropped
}

public readonly record struct TrustAnchorEvent(TrustAnchorEventKind Kind, ushort KeyTag);

/// <summary>One SEP key tracked for a trust point. Identity is the public key, not the key tag.</summary>
public sealed class TrustAnchorRecord
{
    public string Zone { get; set; } = ".";
    public byte Algorithm { get; set; }
    public string PublicKeyBase64 { get; set; } = "";
    public ushort KeyTag { get; set; }
    public byte DigestType { get; set; } = 2;
    public string DigestHex { get; set; } = "";
    public TrustAnchorAcceptance State { get; set; } = TrustAnchorAcceptance.Trusted;
    public DateTimeOffset? PendingSince { get; set; }
}

public sealed class TrustAnchorState
{
    public List<string> RevokedPublicKeysBase64 { get; set; } = [];
    public List<string> RevokedDigests { get; set; } = [];
    public List<TrustAnchorRecord> Entries { get; set; } = [];
}

/// <summary>A DNSKEY from an already-authenticated RRset.</summary>
public sealed record TrustAnchorKeyObservation(
    byte[] PublicKey,
    ushort Flags,
    byte Algorithm,
    ushort KeyTag,
    string DigestHex);

public readonly record struct TrustAnchorUpdateResult(bool Changed, IReadOnlyList<TrustAnchorEvent> Events)
{
    public static TrustAnchorUpdateResult None { get; } = new(false, []);
}

/// <summary>
/// RFC 5011 state machine. The caller has already proved the DNSKEY RRset was signed by a trusted key.
/// A missing trusted key stays; only the REVOKE bit removes one. A pending key that disappears starts over.
/// </summary>
public static class Rfc5011TrustAnchorUpdate
{
    public const ushort SepBit = 0x0001;
    public const ushort RevokeBit = 0x0080;

    public static TrustAnchorUpdateResult Apply(
        TrustAnchorState state,
        IReadOnlyList<TrustAnchorKeyObservation> keys,
        DateTimeOffset now)
    {
        var events = new List<TrustAnchorEvent>();
        var changed = false;

        foreach (var key in keys)
        {
            if ((key.Flags & SepBit) == 0 || (key.Flags & RevokeBit) == 0)
                continue;
            if (key.PublicKey.Length == 0)
                continue;

            var publicKey = Convert.ToBase64String(key.PublicKey);
            var match = FindByPublicKey(state, publicKey);
            if (match is null)
                continue;

            Revoke(state, match, publicKey);
            events.Add(new TrustAnchorEvent(TrustAnchorEventKind.Revoked, match.KeyTag));
            changed = true;
        }

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var key in keys)
        {
            if ((key.Flags & SepBit) == 0 || (key.Flags & RevokeBit) != 0)
                continue;
            if (key.PublicKey.Length == 0)
                continue;

            var publicKey = Convert.ToBase64String(key.PublicKey);
            var digest = NormalizeDigest(key.DigestHex);
            if (IsRevoked(state, publicKey, digest))
                continue;

            seen.Add(publicKey);
            var existing = FindByPublicKey(state, publicKey) ?? FindByDigest(state, digest);
            if (existing is { State: TrustAnchorAcceptance.Trusted })
            {
                if (string.IsNullOrEmpty(existing.PublicKeyBase64))
                {
                    existing.PublicKeyBase64 = publicKey;
                    existing.KeyTag = key.KeyTag;
                    existing.Algorithm = key.Algorithm;
                    changed = true;
                }

                continue;
            }

            if (existing is { State: TrustAnchorAcceptance.Pending })
            {
                existing.PendingSince ??= now;
                if (now - existing.PendingSince.Value >= Rfc5011Timing.AddHoldDown)
                {
                    existing.State = TrustAnchorAcceptance.Trusted;
                    existing.PendingSince = null;
                    events.Add(new TrustAnchorEvent(TrustAnchorEventKind.Trusted, existing.KeyTag));
                    changed = true;
                }

                continue;
            }

            state.Entries.Add(new TrustAnchorRecord
            {
                Zone = ".",
                Algorithm = key.Algorithm,
                PublicKeyBase64 = publicKey,
                KeyTag = key.KeyTag,
                DigestType = 2,
                DigestHex = digest,
                State = TrustAnchorAcceptance.Pending,
                PendingSince = now
            });
            events.Add(new TrustAnchorEvent(TrustAnchorEventKind.Pending, key.KeyTag));
            changed = true;
        }

        for (var i = state.Entries.Count - 1; i >= 0; i--)
        {
            var entry = state.Entries[i];
            if (entry.State != TrustAnchorAcceptance.Pending)
                continue;
            if (string.IsNullOrEmpty(entry.PublicKeyBase64) || seen.Contains(entry.PublicKeyBase64))
                continue;

            events.Add(new TrustAnchorEvent(TrustAnchorEventKind.PendingDropped, entry.KeyTag));
            state.Entries.RemoveAt(i);
            changed = true;
        }

        return new TrustAnchorUpdateResult(changed, events);
    }

    public static string NormalizeDigest(string hex) => hex.Trim().ToUpperInvariant();

    public static bool IsRootZone(string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return true;
        return name.Trim().TrimEnd('.').Length == 0;
    }

    private static void Revoke(TrustAnchorState state, TrustAnchorRecord match, string publicKey)
    {
        state.Entries.Remove(match);
        if (!state.RevokedPublicKeysBase64.Contains(publicKey, StringComparer.Ordinal))
            state.RevokedPublicKeysBase64.Add(publicKey);
        if (!string.IsNullOrWhiteSpace(match.DigestHex))
        {
            var digest = NormalizeDigest(match.DigestHex);
            if (!state.RevokedDigests.Contains(digest, StringComparer.OrdinalIgnoreCase))
                state.RevokedDigests.Add(digest);
        }
    }

    private static bool IsRevoked(TrustAnchorState state, string publicKey, string digest)
        => state.RevokedPublicKeysBase64.Contains(publicKey, StringComparer.Ordinal) ||
           state.RevokedDigests.Contains(digest, StringComparer.OrdinalIgnoreCase);

    private static TrustAnchorRecord? FindByPublicKey(TrustAnchorState state, string publicKey)
        => state.Entries.FirstOrDefault(entry =>
            !string.IsNullOrEmpty(entry.PublicKeyBase64) &&
            string.Equals(entry.PublicKeyBase64, publicKey, StringComparison.Ordinal));

    private static TrustAnchorRecord? FindByDigest(TrustAnchorState state, string digest)
        => state.Entries.FirstOrDefault(entry =>
            !string.IsNullOrWhiteSpace(entry.DigestHex) &&
            string.Equals(NormalizeDigest(entry.DigestHex), digest, StringComparison.OrdinalIgnoreCase));
}
