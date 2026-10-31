using System.Text.Json;
using System.Text.Json.Serialization;

using Dhcpr.Core;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.RootZone;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Validation;

/// <summary>
/// Bootstrap trust anchors from configuration, then the RFC 5011 state file.
/// A configured DS is trusted immediately so an operator can recover a missed rollover.
/// A digest the zone has revoked is not put back.
/// </summary>
public sealed partial class TrustAnchorStore : ITrustAnchorStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() }
    };

    private readonly IOptionsMonitor<DnsConfiguration> _dns;
    private readonly IOptionsMonitor<ApplicationConfiguration> _application;
    private readonly ITrustAnchorDigest _digest;
    private readonly ILogger<TrustAnchorStore> _logger;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly TrustAnchorState _state = new();
    private TrustAnchorConfiguration[] _published = [];
    private int _loaded;
    private int _diskRead;
    private int _subscribed;
    private IDisposable? _subscription;

    public TrustAnchorStore(
        IOptionsMonitor<DnsConfiguration> dns,
        IOptionsMonitor<ApplicationConfiguration> application,
        ITrustAnchorDigest digest,
        ILogger<TrustAnchorStore> logger)
    {
        _dns = dns;
        _application = application;
        _digest = digest;
        _logger = logger;
    }

    public TrustAnchorConfiguration[] GetActiveAnchors()
    {
        if (Volatile.Read(ref _loaded) == 0)
            Load();
        return Volatile.Read(ref _published);
    }

    public async ValueTask<TrustAnchorRefreshOutcome> AcceptDnsKeySetAsync(
        IReadOnlyList<DomainResourceRecord> dnsKeys,
        IReadOnlyList<DomainResourceRecord> rrsigs,
        IDnssecValidator crypto,
        DateTimeOffset now,
        CancellationToken cancellationToken)
    {
        await _gate.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            EnsureLoaded();
            if (MergeConfigured())
                Publish();
            if (!Authenticates(dnsKeys, rrsigs, crypto, now))
                return new TrustAnchorRefreshOutcome { Kind = TrustAnchorRefreshKind.NotAuthenticated };

            var observations = Describe(dnsKeys, crypto);
            var result = Rfc5011TrustAnchorUpdate.Apply(_state, observations, now);
            if (!result.Changed)
            {
                Publish();
                return new TrustAnchorRefreshOutcome
                {
                    Kind = TrustAnchorRefreshKind.Unchanged,
                    Events = result.Events
                };
            }

            await PersistAsync(cancellationToken).ConfigureAwait(false);
            Publish();
            return new TrustAnchorRefreshOutcome
            {
                Kind = TrustAnchorRefreshKind.Updated,
                Events = result.Events
            };
        }
        finally
        {
            _gate.Release();
        }
    }

    private void Load()
    {
        var subscribe = false;
        _gate.Wait();
        try
        {
            if (_loaded != 0)
                return;
            EnsureLoaded();
            MergeConfigured();
            Publish();
            _loaded = 1;
            if (_subscribed == 0)
            {
                _subscribed = 1;
                subscribe = true;
            }
        }
        finally
        {
            _gate.Release();
        }

        if (subscribe)
            _subscription = _dns.OnChange((_, _) => OnConfigurationChanged());
    }

    private void OnConfigurationChanged()
    {
        _gate.Wait();
        try
        {
            if (MergeConfigured())
                Publish();
        }
        finally
        {
            _gate.Release();
        }
    }

    private void EnsureLoaded()
    {
        if (_diskRead != 0)
            return;
        _diskRead = 1;

        var path = _application.CurrentValue.GetTrustAnchorPath();
        if (!File.Exists(path))
            return;

        try
        {
            var json = File.ReadAllText(path);
            var loaded = JsonSerializer.Deserialize<TrustAnchorState>(json, JsonOptions);
            if (loaded is null)
                return;

            _state.RevokedPublicKeysBase64 = loaded.RevokedPublicKeysBase64 ?? [];
            _state.RevokedDigests = loaded.RevokedDigests ?? [];
            _state.Entries = loaded.Entries ?? [];
            LogLoadedTrustAnchorState(_logger, _state.Entries.Count, path);
        }
        catch (Exception ex) when (ex is JsonException or IOException)
        {
            LogTrustAnchorStateUnreadable(_logger, ex, path);
        }
    }

    private bool MergeConfigured()
    {
        var changed = false;
        var anchors = _dns.CurrentValue.TrustAnchors ?? [];
        foreach (var anchor in anchors)
        {
            if (anchor is null || !Rfc5011TrustAnchorUpdate.IsRootZone(anchor.Name))
                continue;
            if (!anchor.TryValidate(out _))
                continue;

            var digest = Rfc5011TrustAnchorUpdate.NormalizeDigest(anchor.DigestHex);
            if (_state.RevokedDigests.Contains(digest, StringComparer.OrdinalIgnoreCase))
                continue;

            var existing = _state.Entries.FirstOrDefault(entry =>
                !string.IsNullOrWhiteSpace(entry.DigestHex) &&
                string.Equals(
                    Rfc5011TrustAnchorUpdate.NormalizeDigest(entry.DigestHex),
                    digest,
                    StringComparison.OrdinalIgnoreCase));
            if (existing is null)
            {
                _state.Entries.Add(new TrustAnchorRecord
                {
                    Zone = ".",
                    Algorithm = anchor.Algorithm,
                    KeyTag = anchor.KeyTag,
                    DigestType = anchor.DigestType,
                    DigestHex = digest,
                    State = TrustAnchorAcceptance.Trusted
                });
                changed = true;
                continue;
            }

            if (existing.State == TrustAnchorAcceptance.Pending)
            {
                existing.State = TrustAnchorAcceptance.Trusted;
                existing.PendingSince = null;
                existing.KeyTag = anchor.KeyTag;
                changed = true;
            }
        }

        return changed;
    }

    private void Publish()
    {
        var list = new List<TrustAnchorConfiguration>();
        var anchors = _dns.CurrentValue.TrustAnchors ?? [];
        foreach (var anchor in anchors)
        {
            if (anchor is null || Rfc5011TrustAnchorUpdate.IsRootZone(anchor.Name))
                continue;
            if (anchor.TryValidate(out _))
                list.Add(anchor);
        }

        foreach (var entry in _state.Entries)
        {
            if (entry.State != TrustAnchorAcceptance.Trusted || string.IsNullOrWhiteSpace(entry.DigestHex))
                continue;

            list.Add(new TrustAnchorConfiguration
            {
                Name = string.IsNullOrWhiteSpace(entry.Zone) ? "." : entry.Zone,
                KeyTag = entry.KeyTag,
                Algorithm = entry.Algorithm,
                DigestType = entry.DigestType == 0 ? (byte)2 : entry.DigestType,
                DigestHex = entry.DigestHex
            });
        }

        Volatile.Write(ref _published, list.ToArray());
    }

    private bool Authenticates(
        IReadOnlyList<DomainResourceRecord> dnsKeys,
        IReadOnlyList<DomainResourceRecord> rrsigs,
        IDnssecValidator crypto,
        DateTimeOffset now)
    {
        var trusted = _state.Entries.Where(static entry => entry.State == TrustAnchorAcceptance.Trusted).ToList();
        if (trusted.Count == 0 || dnsKeys.Count == 0 || rrsigs.Count == 0)
            return false;

        var verificationKeys = new List<DomainResourceRecord>();
        foreach (var record in dnsKeys)
        {
            if (record.Data is not DomainNameSystemKeyData data)
                continue;
            if (MatchesTrusted(record, data, trusted))
                verificationKeys.Add(record);
        }

        if (verificationKeys.Count == 0)
            return false;

        return DnssecRrsetVerifier.TryVerifyRrset(crypto, dnsKeys, rrsigs, verificationKeys, now);
    }

    private bool MatchesTrusted(
        DomainResourceRecord record,
        DomainNameSystemKeyData data,
        List<TrustAnchorRecord> trusted)
    {
        var publicKey = data.PublicKey.IsDefaultOrEmpty
            ? ""
            : Convert.ToBase64String(data.PublicKey.ToArray());
        var digest = _digest.Sha256(record);
        foreach (var entry in trusted)
        {
            if (!string.IsNullOrEmpty(entry.PublicKeyBase64) &&
                string.Equals(entry.PublicKeyBase64, publicKey, StringComparison.Ordinal))
                return true;

            if (!string.IsNullOrWhiteSpace(entry.DigestHex) &&
                string.Equals(entry.DigestHex, digest, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private List<TrustAnchorKeyObservation> Describe(
        IReadOnlyList<DomainResourceRecord> dnsKeys,
        IDnssecValidator crypto)
    {
        var observations = new List<TrustAnchorKeyObservation>();
        foreach (var record in dnsKeys)
        {
            if (record.Type is not DomainRecordType.DNSKEY || record.Name.Count != 0)
                continue;
            if (record.Data is not DomainNameSystemKeyData data || data.PublicKey.IsDefaultOrEmpty)
                continue;

            observations.Add(new TrustAnchorKeyObservation(
                data.PublicKey.ToArray(),
                data.Flags,
                (byte)data.Algorithm,
                crypto.CalculateKeyTag(data, record),
                _digest.Sha256(record)));
        }

        return observations;
    }

    private async Task PersistAsync(CancellationToken cancellationToken)
    {
        var path = _application.CurrentValue.GetTrustAnchorPath();
        var json = JsonSerializer.Serialize(_state, JsonOptions);
        await AtomicFileReplace.WriteAsync(path, json, cancellationToken).ConfigureAwait(false);
        LogPersistedTrustAnchors(_logger, _state.Entries.Count, path);
    }

    [LoggerMessage(Level = LogLevel.Information, Message = "Loaded {Count} trust-anchor record(s) from {Path}")]
    private static partial void LogLoadedTrustAnchorState(ILogger logger, int count, string path);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Trust-anchor state at {Path} could not be read; using configured anchors")]
    private static partial void LogTrustAnchorStateUnreadable(ILogger logger, Exception exception, string path);

    [LoggerMessage(Level = LogLevel.Information, Message = "Wrote {Count} trust-anchor record(s) to {Path}")]
    private static partial void LogPersistedTrustAnchors(ILogger logger, int count, string path);
}
