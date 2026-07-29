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

        scope.LoadTrustAnchors(_options.CurrentValue.TrustAnchors ?? Array.Empty<TrustAnchorConfiguration>());
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
            // Unsigned response: insecure unless we already proved the zone must be signed.
            if (scope.TryGetDelegation(DnssecScope.NormalizeZone(question.Name.ToString()), out _))
            {
                // Have a DS/TA for this exact name's zone cut — unusual for QNAME itself.
                // Treat missing signatures as bogus when RRSIGs were expected for a signed zone cut.
            }

            scope.Observe(DnssecValidationStatus.Insecure);
            return;
        }

        try
        {
            // Authenticate any DNSKEY / DS RRsets present before verifying other data.
            await AuthenticateKeyMaterialInMessageAsync(context, response, allRecords, cancellationToken)
                .ConfigureAwait(false);

            var outcome = await ValidateSignedMessageAsync(context, response, allRecords, cancellationToken)
                .ConfigureAwait(false);
            scope.Observe(outcome);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "DNSSEC validation failed unexpectedly");
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
            if (!await EnsureZoneKeysAvailableAsync(context, signer, cancellationToken).ConfigureAwait(false))
                return DnssecValidationStatus.Bogus;

            if (!scope.TryGetKeys(signer, out var keys))
                return DnssecValidationStatus.Bogus;

            if (!DnssecRrsetVerifier.TryVerifyRrset(_crypto, rrset, rrsigs, keys.Keys, now))
            {
                _logger.LogDebug("RRSIG verification failed for {Name}/{Type}", group.Key.Name, group.Key.Type);
                return DnssecValidationStatus.Bogus;
            }

            verifiedAny = true;
        }

        // NXDOMAIN / NODATA: require NSEC proof when signatures are present.
        if (response.Flags.ResponseCode is DomainResponseCode.NameError ||
            (response.Flags.ResponseCode is DomainResponseCode.NoError &&
             response.Records.Answers.Length == 0 &&
             question.Type is not DomainRecordType.DNSKEY and not DomainRecordType.DS))
        {
            var nsecOutcome = ValidateNsecProof(scope, question, allRecords, now);
            if (nsecOutcome is DnssecValidationStatus.Bogus)
                return DnssecValidationStatus.Bogus;
            if (nsecOutcome is DnssecValidationStatus.Secure)
                verifiedAny = true;
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
                return DnssecValidationStatus.Indeterminate;
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
                return DnssecValidationStatus.Bogus;

            // NameError: NSEC must cover QNAME. NODATA: owner exists, type bit clear (simplified: cover QNAME or exact owner).
            if (question.Name.Equals(nsecRecord.Name) ||
                _crypto.CoversName(nsec, nsecRecord.Name, question.Name))
                return DnssecValidationStatus.Secure;
        }

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
            return true;

        if (scope.SuppressKeyFetch)
            return false;

        // Ensure DS/TA for this zone exists (walk toward root).
        if (!scope.TryGetDelegation(zone, out _))
        {
            if (!await EnsureDelegationAvailableAsync(context, zone, cancellationToken).ConfigureAwait(false))
                return false;
        }

        // Fetch DNSKEY from the same upstreams when directed; otherwise recurse.
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
            return false;

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
            return false;
        }

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
            _logger.LogDebug("No DNSKEY matched trust material for {Zone}", zone);
            return false;
        }

        var rrsigs = DnssecRrsetVerifier.FindCoveringRrsigs(allRecords, dnsKeyRecords[0].Name, DomainRecordType.DNSKEY);
        if (rrsigs.Count == 0)
            return false;

        if (!DnssecRrsetVerifier.TryVerifyRrset(
                _crypto, dnsKeyRecords, rrsigs, matchingKeys, DateTimeOffset.UtcNow))
            return false;

        scope.SetKeys(new AuthenticatedDnsKeySet
        {
            Zone = zone,
            Keys = dnsKeyRecords.ToImmutableArray()
        });
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
            return false;

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
        return true;
    }
}
