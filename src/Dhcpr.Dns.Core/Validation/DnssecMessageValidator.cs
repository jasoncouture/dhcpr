using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Validation;

/// <summary>
/// Validates upstream DNS responses into <see cref="DnssecScope"/>:
/// trust-anchor → DS → DNSKEY → RRSIG, plus NSEC for NXDOMAIN/NODATA.
/// </summary>
public sealed class DnssecMessageValidator
{
    private readonly IDnssecValidator _crypto;
    private readonly IInternalDomainClient _internalClient;
    private readonly IOptionsMonitor<DnsConfiguration> _options;
    private readonly ILogger<DnssecMessageValidator> _logger;

    public DnssecMessageValidator(
        IDnssecValidator crypto,
        IInternalDomainClient internalClient,
        IOptionsMonitor<DnsConfiguration> options,
        ILogger<DnssecMessageValidator> logger)
    {
        _crypto = crypto;
        _internalClient = internalClient;
        _options = options;
        _logger = logger;
    }

    public void EnsureTrustAnchorsLoaded(DnssecScope scope)
    {
        if (scope.TryGetDelegation(".", out _))
            return;

        var anchors = _options.CurrentValue.TrustAnchors ?? Array.Empty<TrustAnchorConfiguration>();
        scope.LoadTrustAnchors(anchors);
        _logger.LogInformation("DNSSEC loaded {Count} trust anchor(s)", anchors.Length);
    }

    public async ValueTask ValidateResponseAsync(
        DomainMessageContext context,
        DomainMessage response,
        CancellationToken cancellationToken)
    {
        var scope = context.DnssecScope;
        if (scope is null)
            return;

        EnsureTrustAnchorsLoaded(scope);

        if (response.Questions.Length == 0)
        {
            _logger.LogInformation("DNSSEC indeterminate: empty question section");
            scope.Observe(DnssecValidationStatus.Indeterminate);
            return;
        }

        var question = response.Questions[0];
        var allRecords = response.Records.Answers
            .Concat(response.Records.Authorities)
            .Concat(response.Records.Additional)
            .ToList();

        var hasRrsig = allRecords.Any(static r => r.Type is DomainRecordType.RRSIG);
        if (!hasRrsig)
        {
            _logger.LogInformation(
                "DNSSEC insecure: no RRSIG in response for {Name}/{Type}",
                question.Name,
                question.Type);
            scope.Observe(DnssecValidationStatus.Insecure);
            return;
        }

        try
        {
            await AuthenticateKeyMaterialInMessageAsync(context, response, allRecords, cancellationToken)
                .ConfigureAwait(false);

            var outcome = await ValidateSignedMessageAsync(context, response, allRecords, cancellationToken)
                .ConfigureAwait(false);
            _logger.LogInformation(
                "DNSSEC signed-message outcome {Outcome} for {Name}/{Type}",
                outcome,
                question.Name,
                question.Type);
            scope.Observe(outcome);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "DNSSEC validation failed unexpectedly for {Name}/{Type}",
                question.Name, question.Type);
            scope.Observe(DnssecValidationStatus.Bogus);
        }
    }

    private async ValueTask AuthenticateKeyMaterialInMessageAsync(
        DomainMessageContext context,
        DomainMessage response,
        List<DomainResourceRecord> allRecords,
        CancellationToken cancellationToken)
    {
        var scope = context.DnssecScope!;

        foreach (var group in DnssecRrsetVerifier.GroupRrsets(allRecords)
                     .Where(static g => g.Key.Type is DomainRecordType.DNSKEY))
        {
            var zone = DnssecScope.NormalizeZone(group.Key.Name.ToString());
            await EnsureDnsKeysAuthenticatedAsync(context, zone, group.ToList(), allRecords, cancellationToken)
                .ConfigureAwait(false);
        }

        foreach (var group in DnssecRrsetVerifier.GroupRrsets(allRecords)
                     .Where(static g => g.Key.Type is DomainRecordType.DS))
        {
            var childZone = DnssecScope.NormalizeZone(group.Key.Name.ToString());
            await EnsureDelegationAuthenticatedAsync(context, childZone, group.ToList(), allRecords, cancellationToken)
                .ConfigureAwait(false);
        }
    }

    private async ValueTask<DnssecValidationStatus> ValidateSignedMessageAsync(
        DomainMessageContext context,
        DomainMessage response,
        List<DomainResourceRecord> allRecords,
        CancellationToken cancellationToken)
    {
        var scope = context.DnssecScope!;
        var question = response.Questions[0];
        var now = DateTimeOffset.UtcNow;

        // Verify each non-DNSSEC RRset that has covering RRSIGs.
        var verifiedAny = false;
        foreach (var group in DnssecRrsetVerifier.GroupRrsets(allRecords))
        {
            if (group.Key.Type is DomainRecordType.DNSKEY or DomainRecordType.DS or DomainRecordType.NSEC
                or DomainRecordType.NSEC3 or DomainRecordType.NSEC3PARAM)
                continue;

            var rrset = group.ToList();
            var rrsigs = DnssecRrsetVerifier.FindCoveringRrsigs(allRecords, group.Key.Name, group.Key.Type);
            if (rrsigs.Count == 0)
                continue;

            var signer = ((ResourceRecordSignatureData)rrsigs[0].Data).SignersName.ToString();
            _logger.LogInformation(
                "DNSSEC verifying {Name}/{Type} ({Count} RR(s), signer={Signer})",
                group.Key.Name,
                group.Key.Type,
                rrset.Count,
                signer);

            if (!await EnsureZoneKeysAvailableAsync(context, signer, cancellationToken).ConfigureAwait(false))
            {
                _logger.LogInformation("DNSSEC bogus: no authenticated keys for signer {Signer}", signer);
                return DnssecValidationStatus.Bogus;
            }

            if (!scope.TryGetKeys(signer, out var keys))
            {
                _logger.LogInformation("DNSSEC bogus: keys missing after ensure for {Signer}", signer);
                return DnssecValidationStatus.Bogus;
            }

            if (!DnssecRrsetVerifier.TryVerifyRrset(_crypto, rrset, rrsigs, keys.Keys, now))
            {
                _logger.LogInformation("DNSSEC bogus: RRSIG verification failed for {Name}/{Type}", group.Key.Name, group.Key.Type);
                return DnssecValidationStatus.Bogus;
            }

            _logger.LogInformation("DNSSEC verified {Name}/{Type}", group.Key.Name, group.Key.Type);
            verifiedAny = true;
        }

        // NXDOMAIN / NODATA: require NSEC proof when signatures are present.
        if (response.Flags.ResponseCode is DomainResponseCode.NameError ||
            (response.Flags.ResponseCode is DomainResponseCode.NoError &&
             response.Records.Answers.Length == 0 &&
             question.Type is not DomainRecordType.DNSKEY and not DomainRecordType.DS))
        {
            _logger.LogInformation(
                "DNSSEC checking NSEC proof for {Name}/{Type} rcode={Rcode}",
                question.Name,
                question.Type,
                response.Flags.ResponseCode);
            var nsecOutcome = ValidateNsecProof(scope, question, allRecords, now);
            if (nsecOutcome is DnssecValidationStatus.Bogus)
            {
                _logger.LogInformation("DNSSEC bogus: NSEC proof failed for {Name}", question.Name);
                return DnssecValidationStatus.Bogus;
            }
            if (nsecOutcome is DnssecValidationStatus.Secure)
                verifiedAny = true;
            else if (nsecOutcome is DnssecValidationStatus.Indeterminate)
                _logger.LogInformation("DNSSEC NSEC3 present but not validated yet for {Name}", question.Name);
        }

        return verifiedAny ? DnssecValidationStatus.Secure : DnssecValidationStatus.Indeterminate;
    }

    private DnssecValidationStatus ValidateNsecProof(
        DnssecScope scope,
        DomainQuestion question,
        List<DomainResourceRecord> allRecords,
        DateTimeOffset now)
    {
        var nsecs = allRecords.Where(static r => r.Type is DomainRecordType.NSEC).ToList();
        if (nsecs.Count == 0)
        {
            // NSEC3 deferred to Phase 5 — signed response without NSEC is indeterminate for now.
            if (allRecords.Any(static r => r.Type is DomainRecordType.NSEC3))
            {
                _logger.LogInformation("DNSSEC NSEC3 proofs not implemented; indeterminate for {Name}", question.Name);
                return DnssecValidationStatus.Indeterminate;
            }

            _logger.LogInformation("DNSSEC no NSEC records for negative proof of {Name}", question.Name);
            return DnssecValidationStatus.Bogus;
        }

        foreach (var nsecRecord in nsecs)
        {
            if (nsecRecord.Data is not NextSecureData nsec)
                continue;

            var rrsigs = DnssecRrsetVerifier.FindCoveringRrsigs(allRecords, nsecRecord.Name, DomainRecordType.NSEC);
            if (rrsigs.Count == 0)
                continue;

            var signer = ((ResourceRecordSignatureData)rrsigs[0].Data).SignersName.ToString();
            if (!scope.TryGetKeys(signer, out var keys))
                continue;

            if (!DnssecRrsetVerifier.TryVerifyRrset(_crypto, [nsecRecord], rrsigs, keys.Keys, now))
            {
                _logger.LogInformation("DNSSEC NSEC RRSIG failed for {Owner}", nsecRecord.Name);
                return DnssecValidationStatus.Bogus;
            }

            // NameError: NSEC must cover QNAME. NODATA: owner exists, type bit clear (simplified: cover QNAME or exact owner).
            if (question.Name.Equals(nsecRecord.Name) ||
                _crypto.CoversName(nsec, nsecRecord.Name, question.Name))
            {
                _logger.LogInformation(
                    "DNSSEC NSEC {Owner} covers {Name} (next={Next})",
                    nsecRecord.Name,
                    question.Name,
                    nsec.NextDomainName);
                return DnssecValidationStatus.Secure;
            }
        }

        _logger.LogInformation("DNSSEC no covering NSEC for {Name}", question.Name);
        return DnssecValidationStatus.Bogus;
    }

    private async ValueTask<bool> EnsureZoneKeysAvailableAsync(
        DomainMessageContext context,
        string zone,
        CancellationToken cancellationToken)
    {
        var scope = context.DnssecScope!;
        zone = DnssecScope.NormalizeZone(zone);
        if (scope.TryGetKeys(zone, out _))
        {
            _logger.LogInformation("DNSSEC keys already authenticated for {Zone}", zone);
            return true;
        }

        if (scope.SuppressKeyFetch)
        {
            _logger.LogInformation("DNSSEC key fetch suppressed for {Zone}", zone);
            return false;
        }

        // Ensure DS/TA for this zone exists (walk toward root).
        if (!scope.TryGetDelegation(zone, out _))
        {
            _logger.LogInformation("DNSSEC ensuring delegation for {Zone}", zone);
            if (!await EnsureDelegationAvailableAsync(context, zone, cancellationToken).ConfigureAwait(false))
            {
                _logger.LogInformation("DNSSEC no delegation available for {Zone}", zone);
                return false;
            }
        }

        // Fetch DNSKEY from the same upstreams when directed; otherwise recurse.
        _logger.LogInformation(
            "DNSSEC fetching DNSKEY for {Zone} (directed={Directed})",
            zone,
            context.UpstreamEndpoints is { Length: > 0 });
        var request = DomainMessage.CreateRequest(
            zone is "." ? DomainLabels.Empty : new DomainLabels(zone),
            DomainRecordType.DNSKEY);
        DomainMessage dnsKeyResponse;
        try
        {
            scope.SuppressKeyFetch = true;
            dnsKeyResponse = context.UpstreamEndpoints is { Length: > 0 } endpoints
                ? await _internalClient.SendAsync(context, request, endpoints, cancellationToken)
                    .ConfigureAwait(false)
                : await _internalClient.SendAsync(context, request, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            scope.SuppressKeyFetch = false;
        }

        var keys = dnsKeyResponse.Records.Answers
            .Where(static r => r.Type is DomainRecordType.DNSKEY)
            .ToList();
        if (keys.Count == 0)
        {
            _logger.LogInformation(
                "DNSSEC DNSKEY fetch for {Zone} returned no keys (rcode={Rcode})",
                zone,
                dnsKeyResponse.Flags.ResponseCode);
            return false;
        }

        var all = dnsKeyResponse.Records.Answers
            .Concat(dnsKeyResponse.Records.Authorities)
            .Concat(dnsKeyResponse.Records.Additional)
            .ToList();

        return await EnsureDnsKeysAuthenticatedAsync(context, zone, keys, all, cancellationToken)
            .ConfigureAwait(false);
    }

    private async ValueTask<bool> EnsureDelegationAvailableAsync(
        DomainMessageContext context,
        string zone,
        CancellationToken cancellationToken)
    {
        var scope = context.DnssecScope!;
        zone = DnssecScope.NormalizeZone(zone);
        if (scope.TryGetDelegation(zone, out _))
            return true;

        if (zone is ".")
        {
            EnsureTrustAnchorsLoaded(scope);
            return scope.TryGetDelegation(".", out _);
        }

        var parent = DnssecScope.ParentZone(zone);
        if (parent is null)
            return false;

        if (!await EnsureZoneKeysAvailableAsync(context, parent, cancellationToken).ConfigureAwait(false))
            return false;

        if (scope.SuppressKeyFetch)
            return false;

        var request = DomainMessage.CreateRequest(zone, DomainRecordType.DS);
        DomainMessage dsResponse;
        try
        {
            scope.SuppressKeyFetch = true;
            dsResponse = context.UpstreamEndpoints is { Length: > 0 } endpoints
                ? await _internalClient.SendAsync(context, request, endpoints, cancellationToken)
                    .ConfigureAwait(false)
                : await _internalClient.SendAsync(context, request, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            scope.SuppressKeyFetch = false;
        }

        var dsRecords = dsResponse.Records.Answers
            .Where(static r => r.Type is DomainRecordType.DS)
            .ToList();

        if (dsRecords.Count == 0)
        {
            // No DS → insecure delegation (not bogus).
            _logger.LogInformation(
                "DNSSEC no DS for {Zone} (rcode={Rcode}); treating as unsigned cut",
                zone,
                dsResponse.Flags.ResponseCode);
            return false;
        }

        _logger.LogInformation("DNSSEC authenticating {Count} DS RR(s) for {Zone}", dsRecords.Count, zone);
        var all = dsResponse.Records.Answers
            .Concat(dsResponse.Records.Authorities)
            .Concat(dsResponse.Records.Additional)
            .ToList();

        return await EnsureDelegationAuthenticatedAsync(context, zone, dsRecords, all, cancellationToken)
            .ConfigureAwait(false);
    }

    private async ValueTask<bool> EnsureDnsKeysAuthenticatedAsync(
        DomainMessageContext context,
        string zone,
        List<DomainResourceRecord> dnsKeyRecords,
        List<DomainResourceRecord> allRecords,
        CancellationToken cancellationToken)
    {
        await ValueTask.CompletedTask.ConfigureAwait(false);
        var scope = context.DnssecScope!;
        zone = DnssecScope.NormalizeZone(zone);

        if (!scope.TryGetDelegation(zone, out var delegation))
        {
            if (zone is ".")
            {
                EnsureTrustAnchorsLoaded(scope);
                if (!scope.TryGetDelegation(".", out delegation))
                    return false;
            }
            else
            {
                return false;
            }
        }

        // Keys that match a DS/TA digest are trusted for verifying the DNSKEY RRset.
        var matchingKeys = new List<DomainResourceRecord>();
        foreach (var keyRecord in dnsKeyRecords)
        {
            if (keyRecord.Data is not DomainNameSystemKeyData)
                continue;

            foreach (var ds in delegation.Digests)
            {
                if (_crypto.VerifyDelegationSigner(ds, keyRecord))
                {
                    matchingKeys.Add(keyRecord);
                    break;
                }
            }
        }

        if (matchingKeys.Count == 0)
        {
            _logger.LogInformation(
                "DNSSEC no DNSKEY matched {Kind} for {Zone} ({KeyCount} key(s) tried)",
                delegation.IsTrustAnchor ? "trust anchor" : "DS",
                zone,
                dnsKeyRecords.Count);
            return false;
        }

        var rrsigs = DnssecRrsetVerifier.FindCoveringRrsigs(allRecords, dnsKeyRecords[0].Name, DomainRecordType.DNSKEY);
        if (rrsigs.Count == 0)
        {
            _logger.LogInformation("DNSSEC DNSKEY RRset for {Zone} has no RRSIG", zone);
            return false;
        }

        if (!DnssecRrsetVerifier.TryVerifyRrset(
                _crypto, dnsKeyRecords, rrsigs, matchingKeys, DateTimeOffset.UtcNow))
        {
            _logger.LogInformation("DNSSEC DNSKEY RRSIG verification failed for {Zone}", zone);
            return false;
        }

        scope.SetKeys(new AuthenticatedDnsKeySet
        {
            Zone = zone,
            Keys = dnsKeyRecords.ToImmutableArray()
        });
        _logger.LogInformation(
            "DNSSEC authenticated {KeyCount} DNSKEY(s) for {Zone} ({MatchCount} matched DS/TA)",
            dnsKeyRecords.Count,
            zone,
            matchingKeys.Count);
        return true;
    }

    private async ValueTask<bool> EnsureDelegationAuthenticatedAsync(
        DomainMessageContext context,
        string childZone,
        List<DomainResourceRecord> dsRecords,
        List<DomainResourceRecord> allRecords,
        CancellationToken cancellationToken)
    {
        var scope = context.DnssecScope!;
        childZone = DnssecScope.NormalizeZone(childZone);
        var parent = DnssecScope.ParentZone(childZone);
        if (parent is null)
            return false;

        if (!await EnsureZoneKeysAvailableAsync(context, parent, cancellationToken).ConfigureAwait(false))
            return false;

        if (!scope.TryGetKeys(parent, out var parentKeys))
            return false;

        var rrsigs = DnssecRrsetVerifier.FindCoveringRrsigs(allRecords, dsRecords[0].Name, DomainRecordType.DS);
        if (rrsigs.Count == 0)
            return false;

        if (!DnssecRrsetVerifier.TryVerifyRrset(
                _crypto, dsRecords, rrsigs, parentKeys.Keys, DateTimeOffset.UtcNow))
        {
            _logger.LogInformation("DNSSEC DS RRSIG verification failed for {Zone} (parent={Parent})", childZone, parent);
            return false;
        }

        var digestsBuilder = ImmutableArray.CreateBuilder<DelegationSignerData>();
        foreach (var record in dsRecords)
        {
            if (record.Data is DelegationSignerData ds)
                digestsBuilder.Add(ds);
        }

        scope.SetDelegation(new AuthenticatedDelegation
        {
            Zone = childZone,
            Digests = digestsBuilder.ToImmutable(),
            IsTrustAnchor = false
        });
        _logger.LogInformation(
            "DNSSEC authenticated {Count} DS RR(s) for {Zone} via parent {Parent}",
            digestsBuilder.Count,
            childZone,
            parent);
        return true;
    }
}
