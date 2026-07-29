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
        _logger.LogDebug("DNSSEC loaded {Count} trust anchor(s)", anchors.Length);
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
            _logger.LogDebug("DNSSEC indeterminate: empty question section");
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
            // Directed internal hops (glue, NS probes, upstream answers) share the client
            // scope. Unsigned glue must not Observe(Insecure) or it clears AD on Secure
            // answers. Client-facing and undirected re-entry (CNAME chase) still count.
            if (context.IsInternal && context.UpstreamEndpoints is { Length: > 0 })
            {
                _logger.LogDebug(
                    "DNSSEC unsigned directed hop ignored for status ({Name}/{Type})",
                    question.Name.ToString(),
                    question.Type);
                return;
            }

            _logger.LogDebug(
                "DNSSEC insecure: no RRSIG in response for {Name}/{Type}",
                question.Name.ToString(),
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
            _logger.LogDebug(
                "DNSSEC signed-message outcome {Outcome} for {Name}/{Type}",
                outcome,
                question.Name.ToString(),
                question.Type);
            if (outcome is DnssecValidationStatus.Bogus)
            {
                _logger.LogDebug(
                    "DNSSEC observing Bogus for {Name}/{Type} (prior status {Prior})",
                    question.Name.ToString(),
                    question.Type,
                    scope.Status);
            }

            scope.Observe(outcome);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "DNSSEC validation failed unexpectedly for {Name}/{Type}",
                question.Name.ToString(), question.Type);
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
            var zone = DnssecScope.NormalizeZone(group.Key.Name);
            await EnsureDnsKeysAuthenticatedAsync(context, zone, group.ToList(), allRecords, cancellationToken)
                .ConfigureAwait(false);
        }

        foreach (var group in DnssecRrsetVerifier.GroupRrsets(allRecords)
                     .Where(static g => g.Key.Type is DomainRecordType.DS))
        {
            var childZone = DnssecScope.NormalizeZone(group.Key.Name);
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

        // Positive answers: verify answer-section RRsets only. Authority/additional on
        // those responses often carry parent NS + glue (or one-RR fragments) whose RRSIGs
        // cover the full set — validating them as Bogus false-SERVFAILs DS/apex queries
        // (cloudflare.net, www.speedtest.net → CDN). Referrals (empty answers + NS) still
        // authenticate the authority NS RRset.
        var isReferral = response.Records.Answers.Length == 0 &&
                         response.Records.Authorities.Any(static r => r.Type is DomainRecordType.NS);
        var rrsetsToVerify = isReferral
            ? response.Records.Authorities
            : response.Records.Answers;

        var verifiedAny = false;
        foreach (var group in DnssecRrsetVerifier.GroupRrsets(rrsetsToVerify))
        {
            if (group.Key.Type is DomainRecordType.DNSKEY or DomainRecordType.DS or DomainRecordType.NSEC
                or DomainRecordType.NSEC3 or DomainRecordType.NSEC3PARAM)
                continue;

            var rrset = group.ToList();
            var owner = new DomainLabels(group.Key.Name);
            var rrsigs = DnssecRrsetVerifier.FindCoveringRrsigs(allRecords, owner, group.Key.Type);
            if (rrsigs.Count == 0)
                continue;

            var signer = ((ResourceRecordSignatureData)rrsigs[0].Data).SignersName.ToString();
            _logger.LogDebug(
                "DNSSEC verifying {Name}/{Type} ({Count} RR(s), signer={Signer})",
                group.Key.Name,
                group.Key.Type,
                rrset.Count,
                signer);

            if (!await EnsureZoneKeysAvailableAsync(context, signer, cancellationToken).ConfigureAwait(false))
            {
                // During key/DS fetch, nested validation cannot pull keys — not Bogus.
                if (scope.SuppressKeyFetch)
                {
                    _logger.LogDebug(
                        "DNSSEC indeterminate: key fetch suppressed for signer {Signer}",
                        signer);
                    return DnssecValidationStatus.Indeterminate;
                }

                _logger.LogDebug("DNSSEC bogus: no authenticated keys for signer {Signer}", signer);
                return DnssecValidationStatus.Bogus;
            }

            if (!scope.TryGetKeys(signer, out var keys))
            {
                _logger.LogDebug("DNSSEC bogus: keys missing after ensure for {Signer}", signer);
                return DnssecValidationStatus.Bogus;
            }

            if (!DnssecRrsetVerifier.TryVerifyRrset(_crypto, rrset, rrsigs, keys.Keys, now))
            {
                _logger.LogDebug(
                    "DNSSEC bogus: RRSIG verification failed for {Name}/{Type}",
                    group.Key.Name,
                    group.Key.Type);
                return DnssecValidationStatus.Bogus;
            }

            _logger.LogDebug("DNSSEC verified {Name}/{Type}", group.Key.Name, group.Key.Type);
            verifiedAny = true;
        }

        // NXDOMAIN / NODATA only — referrals are not denials.
        var needsNegativeProof =
            response.Flags.ResponseCode is DomainResponseCode.NameError ||
            (response.Flags.ResponseCode is DomainResponseCode.NoError &&
             response.Records.Answers.Length == 0 &&
             !isReferral &&
             question.Type is not DomainRecordType.DNSKEY and not DomainRecordType.DS);

        if (needsNegativeProof)
        {
            _logger.LogDebug(
                "DNSSEC checking negative proof for {Name}/{Type} rcode={Rcode}",
                question.Name.ToString(),
                question.Type,
                response.Flags.ResponseCode);
            var nsecOutcome = ValidateNegativeProof(scope, question, response, allRecords, now);
            if (nsecOutcome is DnssecValidationStatus.Bogus)
            {
                _logger.LogDebug("DNSSEC bogus: negative proof failed for {Name}", question.Name.ToString());
                return DnssecValidationStatus.Bogus;
            }

            if (nsecOutcome is DnssecValidationStatus.Secure)
                verifiedAny = true;
            else if (nsecOutcome is DnssecValidationStatus.Insecure)
                return DnssecValidationStatus.Insecure;
        }

        return verifiedAny ? DnssecValidationStatus.Secure : DnssecValidationStatus.Indeterminate;
    }

    private DnssecValidationStatus ValidateNegativeProof(
        DnssecScope scope,
        DomainQuestion question,
        DomainMessage response,
        List<DomainResourceRecord> allRecords,
        DateTimeOffset now)
    {
        var nsecs = allRecords.Where(static r => r.Type is DomainRecordType.NSEC).ToList();
        if (nsecs.Count > 0)
            return ValidateNsecProof(scope, question, nsecs, allRecords, now);

        if (allRecords.Any(static r => r.Type is DomainRecordType.NSEC3))
            return ValidateNsec3Proof(scope, question, response, allRecords, now);

        _logger.LogDebug("DNSSEC no NSEC/NSEC3 records for negative proof of {Name}", question.Name.ToString());
        return DnssecValidationStatus.Bogus;
    }

    private DnssecValidationStatus ValidateNsecProof(
        DnssecScope scope,
        DomainQuestion question,
        List<DomainResourceRecord> nsecs,
        List<DomainResourceRecord> allRecords,
        DateTimeOffset now)
    {
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
                _logger.LogDebug("DNSSEC NSEC RRSIG failed for {Owner}", nsecRecord.Name.ToString());
                return DnssecValidationStatus.Bogus;
            }

            // Exact owner: NODATA when QTYPE (and CNAME) bits are clear.
            if (question.Name.Equals(nsecRecord.Name))
            {
                if (DnssecTypeBitMaps.Contains(nsec.TypeBitMaps, question.Type) ||
                    DnssecTypeBitMaps.Contains(nsec.TypeBitMaps, DomainRecordType.CNAME))
                {
                    _logger.LogDebug(
                        "DNSSEC NSEC NODATA failed: type present on {Owner}",
                        nsecRecord.Name.ToString());
                    return DnssecValidationStatus.Bogus;
                }

                _logger.LogDebug("DNSSEC NSEC NODATA proof for {Name}/{Type}", question.Name.ToString(), question.Type);
                return DnssecValidationStatus.Secure;
            }

            if (_crypto.CoversName(nsec, nsecRecord.Name, question.Name))
            {
                _logger.LogDebug(
                    "DNSSEC NSEC {Owner} covers {Name} (next={Next})",
                    nsecRecord.Name.ToString(),
                    question.Name.ToString(),
                    nsec.NextDomainName.ToString());
                return DnssecValidationStatus.Secure;
            }
        }

        _logger.LogDebug("DNSSEC no covering NSEC for {Name}", question.Name.ToString());
        return DnssecValidationStatus.Bogus;
    }

    private DnssecValidationStatus ValidateNsec3Proof(
        DnssecScope scope,
        DomainQuestion question,
        DomainMessage response,
        List<DomainResourceRecord> allRecords,
        DateTimeOffset now)
    {
        var nsec3s = DnssecNsec3Proof.Collect(allRecords);
        if (nsec3s.Count == 0)
        {
            _logger.LogDebug("DNSSEC NSEC3 owners could not be decoded for {Name}", question.Name.ToString());
            return DnssecValidationStatus.Bogus;
        }

        // Authenticate every NSEC3 RRset before trusting spans.
        foreach (var group in nsec3s.GroupBy(static n => n.Record.Name.ToString(), StringComparer.OrdinalIgnoreCase))
        {
            var records = group.Select(static g => g.Record).ToList();
            var owner = records[0].Name;
            var rrsigs = DnssecRrsetVerifier.FindCoveringRrsigs(allRecords, owner, DomainRecordType.NSEC3);
            if (rrsigs.Count == 0)
            {
                _logger.LogDebug("DNSSEC NSEC3 {Owner} has no RRSIG", owner.ToString());
                return DnssecValidationStatus.Bogus;
            }

            var signer = ((ResourceRecordSignatureData)rrsigs[0].Data).SignersName.ToString();
            if (!scope.TryGetKeys(signer, out var keys))
            {
                _logger.LogDebug("DNSSEC NSEC3 signer keys missing for {Signer}", signer);
                return DnssecValidationStatus.Bogus;
            }

            if (!DnssecRrsetVerifier.TryVerifyRrset(_crypto, records, rrsigs, keys.Keys, now))
            {
                _logger.LogDebug("DNSSEC NSEC3 RRSIG failed for {Owner}", owner.ToString());
                return DnssecValidationStatus.Bogus;
            }
        }

        var parameters = nsec3s[0].Data;
        var qnameHash = _crypto.CalculateNsec3Hash(question.Name, parameters);
        if (qnameHash.Length == 0)
            return DnssecValidationStatus.Bogus;

        // NODATA: exact match on QNAME hash, QTYPE/CNAME bits clear.
        var exact = DnssecNsec3Proof.FindExact(nsec3s, qnameHash);
        if (exact is { } exactMatch &&
            response.Flags.ResponseCode is DomainResponseCode.NoError)
        {
            if (DnssecTypeBitMaps.Contains(exactMatch.Data.TypeBitMaps, question.Type) ||
                DnssecTypeBitMaps.Contains(exactMatch.Data.TypeBitMaps, DomainRecordType.CNAME))
            {
                _logger.LogDebug(
                    "DNSSEC NSEC3 NODATA failed: type present for {Name}",
                    question.Name.ToString());
                return DnssecValidationStatus.Bogus;
            }

            _logger.LogDebug(
                "DNSSEC NSEC3 NODATA proof for {Name}/{Type}",
                question.Name.ToString(),
                question.Type);
            return DnssecValidationStatus.Secure;
        }

        // NXDOMAIN (and name-does-not-exist side of empty non-terminal): closest encloser + next closer (+ wildcard).
        if (!DnssecNsec3Proof.TryFindClosestEncloser(
                _crypto, nsec3s, question.Name, parameters,
                out var closest, out _))
        {
            _logger.LogDebug("DNSSEC NSEC3 closest encloser not found for {Name}", question.Name.ToString());
            return DnssecValidationStatus.Bogus;
        }

        // Exact closest == QNAME was handled above for NODATA; if we are here with NameError and exact match,
        // that is inconsistent (name exists).
        if (exact is not null && response.Flags.ResponseCode is DomainResponseCode.NameError)
        {
            _logger.LogDebug("DNSSEC NSEC3 NXDOMAIN but QNAME hash matches for {Name}", question.Name.ToString());
            return DnssecValidationStatus.Bogus;
        }

        if (closest.Equals(question.Name))
        {
            // Empty non-terminal / NODATA without falling into exact above — treat as NODATA failure.
            _logger.LogDebug("DNSSEC NSEC3 QNAME is closest encloser but NODATA bits failed for {Name}",
                question.Name.ToString());
            return DnssecValidationStatus.Bogus;
        }

        var nextCloser = DnssecNsec3Proof.NextCloser(question.Name, closest);
        if (nextCloser is null)
            return DnssecValidationStatus.Bogus;

        var nextCloserHash = _crypto.CalculateNsec3Hash(nextCloser, parameters);
        var nextCloserCover = DnssecNsec3Proof.FindCover(_crypto, nsec3s, nextCloserHash);
        if (nextCloserCover is null)
        {
            _logger.LogDebug(
                "DNSSEC NSEC3 no cover for next-closer {Next} of {Name}",
                nextCloser.ToString(),
                question.Name.ToString());
            return DnssecValidationStatus.Bogus;
        }

        // Opt-Out: insecure delegations may exist in the span — cannot prove Secure NXDOMAIN.
        if ((nextCloserCover.Value.Data.Flags & DnssecNsec3Proof.OptOutFlag) != 0)
        {
            _logger.LogDebug(
                "DNSSEC NSEC3 Opt-Out cover for next-closer {Next}; insecure for {Name}",
                nextCloser.ToString(),
                question.Name.ToString());
            return DnssecValidationStatus.Insecure;
        }

        if (response.Flags.ResponseCode is DomainResponseCode.NameError)
        {
            var wildcard = DnssecNsec3Proof.WildcardAt(closest);
            var wildcardHash = _crypto.CalculateNsec3Hash(wildcard, parameters);
            // Wildcard may match exactly (exists) or be covered (does not).
            if (DnssecNsec3Proof.FindExact(nsec3s, wildcardHash) is null &&
                DnssecNsec3Proof.FindCover(_crypto, nsec3s, wildcardHash) is null)
            {
                _logger.LogDebug(
                    "DNSSEC NSEC3 no wildcard proof at *.{Closest} for {Name}",
                    closest.ToString(),
                    question.Name.ToString());
                return DnssecValidationStatus.Bogus;
            }
        }

        _logger.LogDebug(
            "DNSSEC NSEC3 proof ok for {Name} (closest={Closest}, next={Next})",
            question.Name.ToString(),
            closest.ToString(),
            nextCloser.ToString());
        return DnssecValidationStatus.Secure;
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
            _logger.LogDebug("DNSSEC keys already authenticated for {Zone}", zone);
            return true;
        }

        if (scope.SuppressKeyFetch)
        {
            _logger.LogDebug("DNSSEC key fetch suppressed for {Zone}", zone);
            return false;
        }

        // Ensure DS/TA for this zone exists (walk toward root).
        if (!scope.TryGetDelegation(zone, out _))
        {
            _logger.LogDebug("DNSSEC ensuring delegation for {Zone}", zone);
            if (!await EnsureDelegationAvailableAsync(context, zone, cancellationToken).ConfigureAwait(false))
            {
                _logger.LogDebug("DNSSEC no delegation available for {Zone}", zone);
                return false;
            }
        }

        // Chain-of-trust material must recurse normally. Reusing this hop's
        // UpstreamEndpoints sends parent/root DNSKEY/DS queries to the wrong NS
        // (e.g. leaf auth servers), which fails validation → Bogus SERVFAIL.
        _logger.LogDebug("DNSSEC fetching DNSKEY for {Zone}", zone);
        var request = DomainMessage.CreateRequest(
            zone is "." ? DomainLabels.Empty : new DomainLabels(zone),
            DomainRecordType.DNSKEY);
        DomainMessage dnsKeyResponse;
        try
        {
            scope.SuppressKeyFetch = true;
            dnsKeyResponse = await _internalClient
                .SendAsync(context, request, cancellationToken)
                .ConfigureAwait(false);
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
            _logger.LogDebug(
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
            // DS lives at the parent — never reuse the child hop's UpstreamEndpoints.
            dsResponse = await _internalClient
                .SendAsync(context, request, cancellationToken)
                .ConfigureAwait(false);
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
            _logger.LogDebug(
                "DNSSEC no DS for {Zone} (rcode={Rcode}); treating as unsigned cut",
                zone,
                dsResponse.Flags.ResponseCode);
            return false;
        }

        _logger.LogDebug("DNSSEC authenticating {Count} DS RR(s) for {Zone}", dsRecords.Count, zone);
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
            _logger.LogDebug(
                "DNSSEC no DNSKEY matched {Kind} for {Zone} ({KeyCount} key(s) tried)",
                delegation.IsTrustAnchor ? "trust anchor" : "DS",
                zone,
                dnsKeyRecords.Count);
            return false;
        }

        var rrsigs = DnssecRrsetVerifier.FindCoveringRrsigs(allRecords, dnsKeyRecords[0].Name, DomainRecordType.DNSKEY);
        if (rrsigs.Count == 0)
        {
            _logger.LogDebug("DNSSEC DNSKEY RRset for {Zone} has no RRSIG", zone);
            return false;
        }

        if (!DnssecRrsetVerifier.TryVerifyRrset(
                _crypto, dnsKeyRecords, rrsigs, matchingKeys, DateTimeOffset.UtcNow))
        {
            _logger.LogDebug("DNSSEC DNSKEY RRSIG verification failed for {Zone}", zone);
            return false;
        }

        scope.SetKeys(new AuthenticatedDnsKeySet
        {
            Zone = zone,
            Keys = dnsKeyRecords.ToImmutableArray()
        });
        _logger.LogDebug(
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
            _logger.LogDebug("DNSSEC DS RRSIG verification failed for {Zone} (parent={Parent})", childZone, parent);
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
        _logger.LogDebug(
            "DNSSEC authenticated {Count} DS RR(s) for {Zone} via parent {Parent}",
            digestsBuilder.Count,
            childZone,
            parent);
        return true;
    }
}
