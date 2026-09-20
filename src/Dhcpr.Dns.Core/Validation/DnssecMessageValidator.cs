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
public sealed partial class DnssecMessageValidator : IDnssecMessageValidator
{
    private readonly IDnssecValidator _crypto;
    private readonly IInternalDomainClient _internalClient;
    private readonly IOptionsMonitor<DnsConfiguration> _options;
    private readonly ILogger<DnssecMessageValidator> _logger;
    private readonly TimeProvider _time;

    public DnssecMessageValidator(
        IDnssecValidator crypto,
        IInternalDomainClient internalClient,
        IOptionsMonitor<DnsConfiguration> options,
        ILogger<DnssecMessageValidator> logger,
        TimeProvider? timeProvider = null)
    {
        _crypto = crypto;
        _internalClient = internalClient;
        _options = options;
        _logger = logger;
        _time = timeProvider ?? TimeProvider.System;
    }

    public void EnsureTrustAnchorsLoaded(DnssecScope scope)
    {
        if (scope.TryGetDelegation(".", out _))
            return;

        var anchors = _options.CurrentValue.TrustAnchors ?? Array.Empty<TrustAnchorConfiguration>();
        scope.LoadTrustAnchors(anchors);
        LogLoadedTrustAnchors(_logger, anchors.Length);
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
            LogEmptyQuestionSection(_logger);
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
                LogUnsignedDirectedHopIgnored(_logger, question.Name, question.Type);
                return;
            }

            LogInsecureNoRrsig(_logger, question.Name, question.Type);
            scope.Observe(DnssecValidationStatus.Insecure);
            return;
        }

        try
        {
            await AuthenticateKeyMaterialInMessageAsync(context, response, allRecords, cancellationToken)
                .ConfigureAwait(false);

            var outcome = await ValidateSignedMessageAsync(context, response, allRecords, cancellationToken)
                .ConfigureAwait(false);
            LogSignedMessageOutcome(_logger, outcome, question.Name, question.Type);
            if (outcome is DnssecValidationStatus.Bogus)
            {
                LogObservingBogus(_logger, question.Name, question.Type, scope.Status);
            }

            scope.Observe(outcome);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogValidationFailedUnexpectedly(_logger, ex, question.Name, question.Type);
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
        var now = _time.GetUtcNow();

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
            LogVerifyingRrset(_logger, group.Key.Name, group.Key.Type, rrset.Count, signer);

            if (!await EnsureZoneKeysAvailableAsync(context, signer, cancellationToken).ConfigureAwait(false))
            {
                // During key/DS fetch, nested validation cannot pull keys — not Bogus.
                if (scope.SuppressKeyFetch)
                {
                    LogKeyFetchSuppressedForSigner(_logger, signer);
                    return DnssecValidationStatus.Indeterminate;
                }

                // Signed child under a parent NODATA DS is insecure, not bogus
                // (qualia.id: RRSIGs exist, id. NSEC proves no DS).
                if (scope.IsInsecureCutOrBelow(signer))
                {
                    LogInsecureUnsignedCut(_logger, signer);
                    return DnssecValidationStatus.Insecure;
                }

                LogNoAuthenticatedKeysForSigner(_logger, signer);
                return DnssecValidationStatus.Bogus;
            }

            if (!scope.TryGetKeys(signer, out var keys))
            {
                LogKeysMissingAfterEnsure(_logger, signer);
                return DnssecValidationStatus.Bogus;
            }

            if (!DnssecRrsetVerifier.TryVerifyRrset(_crypto, rrset, rrsigs, keys.Keys, now))
            {
                LogRrsetVerificationFailed(_logger, group.Key.Name, group.Key.Type);
                return DnssecValidationStatus.Bogus;
            }

            LogVerifiedRrset(_logger, group.Key.Name, group.Key.Type);
            verifiedAny = true;
        }

        // Unsigned answer RRsets (typical: CNAME from an insecure zone before a
        // signed CDN target) must clear AD. Directed hops ignore unsigned glue, so
        // the client-facing assembled answer is where this is enforced.
        if (!isReferral)
        {
            foreach (var group in DnssecRrsetVerifier.GroupRrsets(response.Records.Answers))
            {
                if (group.Key.Type is DomainRecordType.DNSKEY or DomainRecordType.DS
                    or DomainRecordType.NSEC or DomainRecordType.NSEC3 or DomainRecordType.NSEC3PARAM)
                    continue;

                var owner = new DomainLabels(group.Key.Name);
                if (DnssecRrsetVerifier.FindCoveringRrsigs(allRecords, owner, group.Key.Type).Count > 0)
                    continue;

                LogInsecureUnsignedAnswer(_logger, group.Key.Name, group.Key.Type);
                return DnssecValidationStatus.Insecure;
            }
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
            LogCheckingNegativeProof(_logger, question.Name, question.Type, response.Flags.ResponseCode);

            await EnsureNegativeProofKeysAsync(context, allRecords, cancellationToken).ConfigureAwait(false);

            var nsecOutcome = ValidateNegativeProof(scope, question, response, allRecords, now);
            if (nsecOutcome is DnssecValidationStatus.Bogus)
            {
                LogNegativeProofFailed(_logger, question.Name);
                return DnssecValidationStatus.Bogus;
            }

            if (nsecOutcome is DnssecValidationStatus.Secure)
                verifiedAny = true;
            else if (nsecOutcome is DnssecValidationStatus.Insecure)
                return DnssecValidationStatus.Insecure;
            else if (nsecOutcome is DnssecValidationStatus.Indeterminate)
                return DnssecValidationStatus.Indeterminate;
        }

        return verifiedAny ? DnssecValidationStatus.Secure : DnssecValidationStatus.Indeterminate;
    }

    private async ValueTask EnsureNegativeProofKeysAsync(
        DomainMessageContext context,
        List<DomainResourceRecord> allRecords,
        CancellationToken cancellationToken)
    {
        var signers = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var record in allRecords)
        {
            if (record.Type is not (DomainRecordType.NSEC or DomainRecordType.NSEC3))
                continue;
            var rrsigs = DnssecRrsetVerifier.FindCoveringRrsigs(allRecords, record.Name, record.Type);
            foreach (var sigRecord in rrsigs)
            {
                if (sigRecord.Data is ResourceRecordSignatureData rrsig)
                    signers.Add(rrsig.SignersName.ToString());
            }
        }

        foreach (var signer in signers)
            await EnsureZoneKeysAvailableAsync(context, signer, cancellationToken).ConfigureAwait(false);
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

        LogNoNegativeProofRecords(_logger, question.Name);
        return DnssecValidationStatus.Bogus;
    }

    private DnssecValidationStatus ValidateNsecProof(
        DnssecScope scope,
        DomainQuestion question,
        List<DomainResourceRecord> nsecs,
        List<DomainResourceRecord> allRecords,
        DateTimeOffset now)
    {
        var sawSignedNsecWithoutKeys = false;
        foreach (var nsecRecord in nsecs)
        {
            if (nsecRecord.Data is not NextSecureData nsec)
                continue;

            var rrsigs = DnssecRrsetVerifier.FindCoveringRrsigs(allRecords, nsecRecord.Name, DomainRecordType.NSEC);
            if (rrsigs.Count == 0)
                continue;

            var signer = ((ResourceRecordSignatureData)rrsigs[0].Data).SignersName.ToString();
            if (!scope.TryGetKeys(signer, out var keys))
            {
                // Zone-walk NS probes often see NSEC before the signer’s DNSKEY is cached
                // in this scope. Missing keys must not sticky-Bogus the client query.
                sawSignedNsecWithoutKeys = true;
                LogNsecSignerKeysMissing(_logger, signer, nsecRecord.Name);
                continue;
            }

            if (!DnssecRrsetVerifier.TryVerifyRrset(_crypto, [nsecRecord], rrsigs, keys.Keys, now))
            {
                LogNsecRrsigFailed(_logger, nsecRecord.Name);
                return DnssecValidationStatus.Bogus;
            }

            // Exact owner: NODATA when QTYPE (and CNAME) bits are clear.
            if (question.Name.Equals(nsecRecord.Name))
            {
                if (DnssecTypeBitMaps.Contains(nsec.TypeBitMaps, question.Type) ||
                    DnssecTypeBitMaps.Contains(nsec.TypeBitMaps, DomainRecordType.CNAME))
                {
                    LogNsecNodataTypePresent(_logger, nsecRecord.Name);
                    return DnssecValidationStatus.Bogus;
                }

                LogNsecNodataProof(_logger, question.Name, question.Type);
                return DnssecValidationStatus.Secure;
            }

            if (_crypto.CoversName(nsec, nsecRecord.Name, question.Name))
            {
                LogNsecCoversName(_logger, nsecRecord.Name, question.Name, nsec.NextDomainName);
                return DnssecValidationStatus.Secure;
            }
        }

        if (sawSignedNsecWithoutKeys)
        {
            LogSignedNsecWithoutKeys(_logger, question.Name);
            return DnssecValidationStatus.Indeterminate;
        }

        LogNoCoveringNsec(_logger, question.Name);
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
            LogNsec3OwnersUndecodable(_logger, question.Name);
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
                LogNsec3HasNoRrsig(_logger, owner);
                return DnssecValidationStatus.Bogus;
            }

            var signer = ((ResourceRecordSignatureData)rrsigs[0].Data).SignersName.ToString();
            if (!scope.TryGetKeys(signer, out var keys))
            {
                LogNsec3SignerKeysMissing(_logger, signer);
                return DnssecValidationStatus.Indeterminate;
            }

            if (!DnssecRrsetVerifier.TryVerifyRrset(_crypto, records, rrsigs, keys.Keys, now))
            {
                LogNsec3RrsigFailed(_logger, owner);
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
                LogNsec3NodataTypePresent(_logger, question.Name);
                return DnssecValidationStatus.Bogus;
            }

            LogNsec3NodataProof(_logger, question.Name, question.Type);
            return DnssecValidationStatus.Secure;
        }

        // NXDOMAIN (and name-does-not-exist side of empty non-terminal): closest encloser + next closer (+ wildcard).
        if (!DnssecNsec3Proof.TryFindClosestEncloser(
                _crypto, nsec3s, question.Name, parameters,
                out var closest, out _))
        {
            LogNsec3ClosestEncloserNotFound(_logger, question.Name);
            return DnssecValidationStatus.Bogus;
        }

        // Exact closest == QNAME was handled above for NODATA; if we are here with NameError and exact match,
        // that is inconsistent (name exists).
        if (exact is not null && response.Flags.ResponseCode is DomainResponseCode.NameError)
        {
            LogNsec3NxdomainQnameMatches(_logger, question.Name);
            return DnssecValidationStatus.Bogus;
        }

        if (closest.Equals(question.Name))
        {
            // Empty non-terminal / NODATA without falling into exact above — treat as NODATA failure.
            LogNsec3QnameIsClosestEncloser(_logger, question.Name);
            return DnssecValidationStatus.Bogus;
        }

        var nextCloser = DnssecNsec3Proof.NextCloser(question.Name, closest);
        if (nextCloser is null)
            return DnssecValidationStatus.Bogus;

        var nextCloserHash = _crypto.CalculateNsec3Hash(nextCloser, parameters);
        var nextCloserCover = DnssecNsec3Proof.FindCover(_crypto, nsec3s, nextCloserHash);
        if (nextCloserCover is null)
        {
            LogNsec3NoNextCloserCover(_logger, nextCloser, question.Name);
            return DnssecValidationStatus.Bogus;
        }

        // Opt-Out: insecure delegations may exist in the span — cannot prove Secure NXDOMAIN.
        if ((nextCloserCover.Value.Data.Flags & DnssecNsec3Proof.OptOutFlag) != 0)
        {
            LogNsec3OptOutCover(_logger, nextCloser, question.Name);
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
                LogNsec3NoWildcardProof(_logger, closest, question.Name);
                return DnssecValidationStatus.Bogus;
            }
        }

        LogNsec3ProofOk(_logger, question.Name, closest, nextCloser);
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
            LogKeysAlreadyAuthenticated(_logger, zone);
            return true;
        }

        if (scope.SuppressKeyFetch)
        {
            LogKeyFetchSuppressedForZone(_logger, zone);
            return false;
        }

        // Ensure DS/TA for this zone exists (walk toward root).
        if (!scope.TryGetDelegation(zone, out _))
        {
            LogEnsuringDelegation(_logger, zone);
            if (!await EnsureDelegationAvailableAsync(context, zone, cancellationToken).ConfigureAwait(false))
            {
                LogNoDelegationAvailable(_logger, zone);
                return false;
            }
        }

        // Chain-of-trust material must recurse normally. Reusing this hop's
        // UpstreamEndpoints sends parent/root DNSKEY/DS queries to the wrong NS
        // (e.g. leaf auth servers), which fails validation → Bogus SERVFAIL.
        LogFetchingDnsKey(_logger, zone);
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
            LogDnsKeyFetchReturnedNoKeys(_logger, zone, dnsKeyResponse.Flags.ResponseCode);
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
            // No DS → insecure delegation (not bogus). Only NODATA/NXDOMAIN
            // prove absence; SERVFAIL/timeout must not fail open.
            LogNoDsUnsignedCut(_logger, zone, dsResponse.Flags.ResponseCode);
            if (dsResponse.Flags.ResponseCode is DomainResponseCode.NoError
                or DomainResponseCode.NameError)
                scope.MarkInsecureCut(zone);
            return false;
        }

        LogAuthenticatingDs(_logger, dsRecords.Count, zone);
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
        await Task.Yield();
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
            LogNoDnsKeyMatched(_logger, delegation.IsTrustAnchor ? "trust anchor" : "DS", zone, dnsKeyRecords.Count);
            return false;
        }

        var rrsigs = DnssecRrsetVerifier.FindCoveringRrsigs(allRecords, dnsKeyRecords[0].Name, DomainRecordType.DNSKEY);
        if (rrsigs.Count == 0)
        {
            LogDnsKeyRrsetHasNoRrsig(_logger, zone);
            return false;
        }

        if (!DnssecRrsetVerifier.TryVerifyRrset(
                _crypto, dnsKeyRecords, rrsigs, matchingKeys, _time.GetUtcNow()))
        {
            LogDnsKeyRrsigFailed(_logger, zone);
            return false;
        }

        scope.SetKeys(new AuthenticatedDnsKeySet
        {
            Zone = zone,
            Keys = dnsKeyRecords.ToImmutableArray()
        });
        LogAuthenticatedDnsKeys(_logger, dnsKeyRecords.Count, zone, matchingKeys.Count);
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
                _crypto, dsRecords, rrsigs, parentKeys.Keys, _time.GetUtcNow()))
        {
            LogDsRrsigFailed(_logger, childZone, parent);
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
        LogAuthenticatedDs(_logger, digestsBuilder.Count, childZone, parent);
        return true;
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC loaded {Count} trust anchor(s)")]
    private static partial void LogLoadedTrustAnchors(ILogger logger, int count);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC indeterminate: empty question section")]
    private static partial void LogEmptyQuestionSection(ILogger logger);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC unsigned directed hop ignored for status ({Name}/{Type})")]
    private static partial void LogUnsignedDirectedHopIgnored(ILogger logger, DomainLabels name, DomainRecordType type);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC insecure: no RRSIG in response for {Name}/{Type}")]
    private static partial void LogInsecureNoRrsig(ILogger logger, DomainLabels name, DomainRecordType type);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC signed-message outcome {Outcome} for {Name}/{Type}")]
    private static partial void LogSignedMessageOutcome(ILogger logger, DnssecValidationStatus outcome, DomainLabels name, DomainRecordType type);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC observing Bogus for {Name}/{Type} (prior status {Prior})")]
    private static partial void LogObservingBogus(ILogger logger, DomainLabels name, DomainRecordType type, DnssecValidationStatus prior);

    [LoggerMessage(Level = LogLevel.Warning, Message = "DNSSEC validation failed unexpectedly for {Name}/{Type}")]
    private static partial void LogValidationFailedUnexpectedly(ILogger logger, Exception exception, DomainLabels name, DomainRecordType type);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC verifying {Name}/{Type} ({Count} RR(s), signer={Signer})")]
    private static partial void LogVerifyingRrset(ILogger logger, string name, DomainRecordType type, int count, string signer);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC indeterminate: key fetch suppressed for signer {Signer}")]
    private static partial void LogKeyFetchSuppressedForSigner(ILogger logger, string signer);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC bogus: no authenticated keys for signer {Signer}")]
    private static partial void LogNoAuthenticatedKeysForSigner(ILogger logger, string signer);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC insecure cut: no DS for signer {Signer}")]
    private static partial void LogInsecureUnsignedCut(ILogger logger, string signer);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC bogus: keys missing after ensure for {Signer}")]
    private static partial void LogKeysMissingAfterEnsure(ILogger logger, string signer);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC bogus: RRSIG verification failed for {Name}/{Type}")]
    private static partial void LogRrsetVerificationFailed(ILogger logger, string name, DomainRecordType type);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC verified {Name}/{Type}")]
    private static partial void LogVerifiedRrset(ILogger logger, string name, DomainRecordType type);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC insecure: unsigned answer RRset {Name}/{Type}")]
    private static partial void LogInsecureUnsignedAnswer(ILogger logger, string name, DomainRecordType type);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC checking negative proof for {Name}/{Type} rcode={Rcode}")]
    private static partial void LogCheckingNegativeProof(ILogger logger, DomainLabels name, DomainRecordType type, DomainResponseCode rcode);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC bogus: negative proof failed for {Name}")]
    private static partial void LogNegativeProofFailed(ILogger logger, DomainLabels name);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC no NSEC/NSEC3 records for negative proof of {Name}")]
    private static partial void LogNoNegativeProofRecords(ILogger logger, DomainLabels name);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC NSEC signer keys missing for {Signer} (owner={Owner})")]
    private static partial void LogNsecSignerKeysMissing(ILogger logger, string signer, DomainLabels owner);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC NSEC RRSIG failed for {Owner}")]
    private static partial void LogNsecRrsigFailed(ILogger logger, DomainLabels owner);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC NSEC NODATA failed: type present on {Owner}")]
    private static partial void LogNsecNodataTypePresent(ILogger logger, DomainLabels owner);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC NSEC NODATA proof for {Name}/{Type}")]
    private static partial void LogNsecNodataProof(ILogger logger, DomainLabels name, DomainRecordType type);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC NSEC {Owner} covers {Name} (next={Next})")]
    private static partial void LogNsecCoversName(ILogger logger, DomainLabels owner, DomainLabels name, DomainLabels next);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC indeterminate: signed NSEC present but no keys for {Name}")]
    private static partial void LogSignedNsecWithoutKeys(ILogger logger, DomainLabels name);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC no covering NSEC for {Name}")]
    private static partial void LogNoCoveringNsec(ILogger logger, DomainLabels name);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC NSEC3 owners could not be decoded for {Name}")]
    private static partial void LogNsec3OwnersUndecodable(ILogger logger, DomainLabels name);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC NSEC3 {Owner} has no RRSIG")]
    private static partial void LogNsec3HasNoRrsig(ILogger logger, DomainLabels owner);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC indeterminate: NSEC3 signer keys missing for {Signer}")]
    private static partial void LogNsec3SignerKeysMissing(ILogger logger, string signer);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC NSEC3 RRSIG failed for {Owner}")]
    private static partial void LogNsec3RrsigFailed(ILogger logger, DomainLabels owner);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC NSEC3 NODATA failed: type present for {Name}")]
    private static partial void LogNsec3NodataTypePresent(ILogger logger, DomainLabels name);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC NSEC3 NODATA proof for {Name}/{Type}")]
    private static partial void LogNsec3NodataProof(ILogger logger, DomainLabels name, DomainRecordType type);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC NSEC3 closest encloser not found for {Name}")]
    private static partial void LogNsec3ClosestEncloserNotFound(ILogger logger, DomainLabels name);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC NSEC3 NXDOMAIN but QNAME hash matches for {Name}")]
    private static partial void LogNsec3NxdomainQnameMatches(ILogger logger, DomainLabels name);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC NSEC3 QNAME is closest encloser but NODATA bits failed for {Name}")]
    private static partial void LogNsec3QnameIsClosestEncloser(ILogger logger, DomainLabels name);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC NSEC3 no cover for next-closer {Next} of {Name}")]
    private static partial void LogNsec3NoNextCloserCover(ILogger logger, DomainLabels next, DomainLabels name);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC NSEC3 Opt-Out cover for next-closer {Next}; insecure for {Name}")]
    private static partial void LogNsec3OptOutCover(ILogger logger, DomainLabels next, DomainLabels name);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC NSEC3 no wildcard proof at *.{Closest} for {Name}")]
    private static partial void LogNsec3NoWildcardProof(ILogger logger, DomainLabels closest, DomainLabels name);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC NSEC3 proof ok for {Name} (closest={Closest}, next={Next})")]
    private static partial void LogNsec3ProofOk(ILogger logger, DomainLabels name, DomainLabels closest, DomainLabels next);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC keys already authenticated for {Zone}")]
    private static partial void LogKeysAlreadyAuthenticated(ILogger logger, string zone);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC key fetch suppressed for {Zone}")]
    private static partial void LogKeyFetchSuppressedForZone(ILogger logger, string zone);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC ensuring delegation for {Zone}")]
    private static partial void LogEnsuringDelegation(ILogger logger, string zone);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC no delegation available for {Zone}")]
    private static partial void LogNoDelegationAvailable(ILogger logger, string zone);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC fetching DNSKEY for {Zone}")]
    private static partial void LogFetchingDnsKey(ILogger logger, string zone);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC DNSKEY fetch for {Zone} returned no keys (rcode={Rcode})")]
    private static partial void LogDnsKeyFetchReturnedNoKeys(ILogger logger, string zone, DomainResponseCode rcode);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC no DS for {Zone} (rcode={Rcode}); treating as unsigned cut")]
    private static partial void LogNoDsUnsignedCut(ILogger logger, string zone, DomainResponseCode rcode);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC authenticating {Count} DS RR(s) for {Zone}")]
    private static partial void LogAuthenticatingDs(ILogger logger, int count, string zone);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC no DNSKEY matched {Kind} for {Zone} ({KeyCount} key(s) tried)")]
    private static partial void LogNoDnsKeyMatched(ILogger logger, string kind, string zone, int keyCount);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC DNSKEY RRset for {Zone} has no RRSIG")]
    private static partial void LogDnsKeyRrsetHasNoRrsig(ILogger logger, string zone);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC DNSKEY RRSIG verification failed for {Zone}")]
    private static partial void LogDnsKeyRrsigFailed(ILogger logger, string zone);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC authenticated {KeyCount} DNSKEY(s) for {Zone} ({MatchCount} matched DS/TA)")]
    private static partial void LogAuthenticatedDnsKeys(ILogger logger, int keyCount, string zone, int matchCount);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC DS RRSIG verification failed for {Zone} (parent={Parent})")]
    private static partial void LogDsRrsigFailed(ILogger logger, string zone, string parent);

    [LoggerMessage(Level = LogLevel.Debug, Message = "DNSSEC authenticated {Count} DS RR(s) for {Zone} via parent {Parent}")]
    private static partial void LogAuthenticatedDs(ILogger logger, int count, string zone, string parent);
}
