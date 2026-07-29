using System.Collections.Concurrent;
using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Protocol.Zone;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public enum DnssecValidationStatus
{
    Unchecked,
    Secure,
    Insecure,
    Bogus,
    Indeterminate
}

/// <summary>Authenticated DNSKEY set for a zone apex.</summary>
public sealed class AuthenticatedDnsKeySet
{
    public required string Zone { get; init; }
    public required ImmutableArray<DomainResourceRecord> Keys { get; init; }
}

/// <summary>Authenticated DS set (or trust-anchor equivalent) for a child zone.</summary>
public sealed class AuthenticatedDelegation
{
    public required string Zone { get; init; }
    public required ImmutableArray<DelegationSignerData> Digests { get; init; }
    /// <summary>True when this is a configured trust anchor, not a fetched DS RRset.</summary>
    public bool IsTrustAnchor { get; init; }
}

public sealed class DnssecScope
{
    private readonly ConcurrentDictionary<string, AuthenticatedDnsKeySet> _keys =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly ConcurrentDictionary<string, AuthenticatedDelegation> _delegations =
        new(StringComparer.OrdinalIgnoreCase);

    public DnssecValidationStatus Status { get; private set; } = DnssecValidationStatus.Unchecked;

    /// <summary>True while fetching DS/DNSKEY so nested validation does not re-enter fetch loops.</summary>
    public bool SuppressKeyFetch { get; set; }

    public void LoadTrustAnchors(IEnumerable<TrustAnchorConfiguration> anchors)
    {
        foreach (var anchor in anchors)
        {
            if (!anchor.TryValidate(out _))
                continue;

            var zone = RootZoneSnapshot.NormalizeOwner(anchor.Name);
            if (zone.Length == 0)
                zone = ".";

            byte[] digest;
            try
            {
                digest = Convert.FromHexString(anchor.DigestHex);
            }
            catch
            {
                continue;
            }

            var ds = new DelegationSignerData(
                anchor.KeyTag,
                (DnssecAlgorithmType)anchor.Algorithm,
                (DelegationSignerDigestType)anchor.DigestType,
                digest.ToImmutableArray());

            _delegations[zone] = new AuthenticatedDelegation
            {
                Zone = zone,
                Digests = [ds],
                IsTrustAnchor = true
            };
        }
    }

    public bool TryGetKeys(string zone, out AuthenticatedDnsKeySet keys)
        => _keys.TryGetValue(NormalizeZone(zone), out keys!);

    public bool TryGetDelegation(string zone, out AuthenticatedDelegation delegation)
        => _delegations.TryGetValue(NormalizeZone(zone), out delegation!);

    public void SetKeys(AuthenticatedDnsKeySet keys)
        => _keys[NormalizeZone(keys.Zone)] = keys;

    public void SetDelegation(AuthenticatedDelegation delegation)
        => _delegations[NormalizeZone(delegation.Zone)] = delegation;

    public void Observe(DnssecValidationStatus outcome)
    {
        Status = Combine(Status, outcome);
    }

    public static DnssecValidationStatus Combine(DnssecValidationStatus current, DnssecValidationStatus next)
    {
        if (current is DnssecValidationStatus.Bogus || next is DnssecValidationStatus.Bogus)
            return DnssecValidationStatus.Bogus;

        if (current is DnssecValidationStatus.Unchecked)
            return next;

        if (next is DnssecValidationStatus.Unchecked or DnssecValidationStatus.Indeterminate)
            return current;

        if (current is DnssecValidationStatus.Indeterminate)
            return next;

        // Secure + Insecure → Insecure (AD must stay off).
        if (current is DnssecValidationStatus.Insecure || next is DnssecValidationStatus.Insecure)
            return DnssecValidationStatus.Insecure;

        return DnssecValidationStatus.Secure;
    }

    public static string NormalizeZone(string zone)
    {
        var normalized = RootZoneSnapshot.NormalizeOwner(zone);
        return normalized.Length == 0 ? "." : normalized;
    }

    public static string? ParentZone(string zone)
    {
        var normalized = NormalizeZone(zone);
        if (normalized is ".")
            return null;

        var dot = normalized.IndexOf('.');
        return dot < 0 ? "." : normalized[(dot + 1)..];
    }
}
