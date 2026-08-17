using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Net;

using Dhcpr.Core;
using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Protocol.Zone;
using Dhcpr.Dns.Core.RootZone;

using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

public sealed class RecursiveRootResolver : IDomainMessageMiddleware
{
    private readonly IInternalDomainClient _internalClient;
    private readonly ILogger<RecursiveRootResolver> _logger;
    private readonly IRootServerTips _rootServerTips;

    public RecursiveRootResolver(
        IRootServerTips rootServerTips,
        IInternalDomainClient internalClient,
        ILogger<RecursiveRootResolver> logger
    )
    {
        _rootServerTips = rootServerTips;
        _internalClient = internalClient;
        _logger = logger;
    }

    public async ValueTask<DomainMessage?> ProcessAsync(DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        // Directed upstream hops are owned by UpstreamQueryMiddleware.
        if (context.UpstreamEndpoints is { Length: > 0 })
            return null;

        var question = context.DomainMessage.Questions[0];
        var remainingLabels = question.Name.Labels;
        using var rootEndPoints = ListPool<IPEndPoint>.Default.Get();
        rootEndPoints.AddRange(_rootServerTips.GetEndpoints().OrderBy(_ => Random.Shared.Next()));
        using var zoneLabels = ListPool<DomainLabel>.Default.Get();
        using var addressRecords = ListPool<IPAddress>.Default.Get();
        try
        {
            // Descend label by label looking for zone cuts. Do not probe the leaf —
            // parent nameservers refer, then QueryFollowingReferralsAsync asks the
            // child for the real QTYPE (NS/SOA/DNSKEY must not stop at the TLD).
            while (remainingLabels.Length > 0)
            {
                addressRecords.Clear();
                var next = remainingLabels[^1];
                remainingLabels = remainingLabels[..^1];
                zoneLabels.Insert(0, next);

                if (remainingLabels.Length == 0)
                    break;

                var message = DomainMessage.CreateRequest(
                    new DomainLabels(zoneLabels.ToImmutableArray()),
                    DomainRecordType.NS);

                // Zone-cut discovery shares the client DnssecScope. NODATA/NSEC from
                // intermediate labels (e.g. cdn.cloudflare.net) must not Observe into
                // Status — that sticky-Bogus’d deep CDN names like speedtest’s target.
                context.DnssecScope?.PushIgnoreStatus();
                DomainMessage responseMessage;
                try
                {
                    responseMessage = await QueryUpstreamAsync(
                        context, message, rootEndPoints, cancellationToken);
                }
                finally
                {
                    context.DnssecScope?.PopIgnoreStatus();
                }

                using var nsNames = GetNameserverNames(
                    responseMessage.Records, message.Questions[0].Name).ToPooledList();

                // Authoritative NODATA / no referral — keep current nameservers and continue.
                if (nsNames.Count == 0)
                    continue;

                var nsNameSet = nsNames.ToHashSet(StringComparer.OrdinalIgnoreCase);
                addressRecords.AddRange(GetGlueAddresses(responseMessage.Records, nsNameSet));

                if (addressRecords.Count == 0)
                    addressRecords.AddRange(
                        await ResolveNameserverAddressesAsync(context, nsNames, rootEndPoints, cancellationToken));

                // Could not resolve NS addresses — keep current endpoints.
                if (addressRecords.Count == 0)
                    continue;

                rootEndPoints.Clear();
                rootEndPoints.AddRange(addressRecords.Select(i => new IPEndPoint(i, 53)));
            }

            var cloned = context.DomainMessage with { Id = (ushort)Random.Shared.Next(0, ushort.MaxValue + 1) };
            var result = await QueryFollowingReferralsAsync(
                context, cloned, rootEndPoints, cancellationToken);

            if (result.Records.Answers.Length != 0 ||
                cloned.Questions[0].Type is not (DomainRecordType.A or DomainRecordType.AAAA))
            {
                return FinalizeRecursiveResponse(context.DomainMessage, result);
            }

            cloned = cloned with
            {
                Questions = cloned.Questions.Select(x => x with { Type = DomainRecordType.CNAME })
                    .ToImmutableArray()
            };
            var cnameResponse =
                await QueryFollowingReferralsAsync(
                    context, cloned, rootEndPoints, cancellationToken);
            if (cnameResponse.Records.Answers.Length > 0 &&
                cnameResponse.Flags.ResponseCode is DomainResponseCode.NoError)
            {
                return FinalizeRecursiveResponse(context.DomainMessage, cnameResponse);
            }

            return FinalizeRecursiveResponse(context.DomainMessage, result);
        }
        catch (Exception ex)
        {
            if (!cancellationToken.IsCancellationRequested)
            {
                _logger.LogError(ex, "An unhandled exception occurred while resolving recursively.");
            }

            context.ServFailReason = "recursive resolver exception";
            return DomainMessage.CreateResponse(context.DomainMessage, DomainResourceRecords.Empty,
                DomainResponseCode.ServerFailure);
        }
    }

    private async ValueTask<DomainMessage> QueryUpstreamAsync(
        DomainMessageContext parentContext,
        DomainMessage message,
        PooledList<IPEndPoint> endPoints,
        CancellationToken cancellationToken)
    {
        var upstream = endPoints
            .OrderBy(_ => Random.Shared.Next())
            .ToImmutableArray();
        return await _internalClient.SendAsync(parentContext, message, upstream, cancellationToken);
    }

    private async ValueTask<DomainMessage> QueryFollowingReferralsAsync(
        DomainMessageContext parentContext,
        DomainMessage request,
        PooledList<IPEndPoint> endPoints,
        CancellationToken cancellationToken)
    {
        const int maxReferralDepth = 8;
        DomainMessage? last = null;

        for (var depth = 0; depth < maxReferralDepth; depth++)
        {
            last = await QueryUpstreamAsync(parentContext, request, endPoints, cancellationToken);

            // TLD servers often echo delegation NS in ANSWER for QTYPE NS without AA.
            // That is still a referral — the signed apex RRset is on the child.
            if (last.Flags.Authoritative && last.Records.Answers.Length > 0)
                return last;

            if (TryPromoteAuthoritativeAnswer(request, last) is { } promoted)
                return promoted;

            using var nsNames = GetNameserverNames(last.Records, request.Questions[0].Name).ToPooledList();
            if (nsNames.Count == 0)
                return last;

            var nsNameSet = nsNames.ToHashSet(StringComparer.OrdinalIgnoreCase);
            using var referralAddresses = GetGlueAddresses(last.Records, nsNameSet).ToPooledList();
            if (referralAddresses.Count == 0)
            {
                referralAddresses.AddRange(
                    await ResolveNameserverAddressesAsync(parentContext, nsNames, endPoints, cancellationToken));
                if (referralAddresses.Count == 0)
                    return ServFail(request);
            }

            // Parent NODATA often repeats the current zone's NS in AUTHORITY.
            // Following those is a self-referral loop → SERVFAIL (cert-manager NS walk).
            var currentAddresses = endPoints.Select(static e => e.Address).ToHashSet();
            if (referralAddresses.All(currentAddresses.Contains))
                return last;

            endPoints.Clear();
            endPoints.AddRange(referralAddresses.Select(i => new IPEndPoint(i, 53)));
        }

        if (!last!.Flags.Authoritative &&
            request.Questions[0].Type is DomainRecordType.NS or DomainRecordType.SOA
                or DomainRecordType.DNSKEY)
            return ServFail(request);

        return IsUnresolvedReferral(last) ? ServFail(request) : last!;
    }

    private static DomainMessage FinalizeRecursiveResponse(DomainMessage request, DomainMessage response)
    {
        if (TryPromoteAuthoritativeAnswer(request, response) is { } promoted)
            response = promoted;
        if (IsUnresolvedReferral(response))
            return ServFail(request);
        return StripParentDelegationProof(request, response);
    }

    /// <summary>
    /// Move an AA child's QTYPE RRset (plus covering RRSIGs) from AUTHORITY to
    /// ANSWER. Parent referrals are AA=0 and must be followed, not copied.
    /// </summary>
    private static DomainMessage? TryPromoteAuthoritativeAnswer(DomainMessage request, DomainMessage response)
    {
        if (!response.Flags.Authoritative)
            return null;
        if (request.Questions.Length == 0)
            return null;
        if (response.Flags.ResponseCode is not DomainResponseCode.NoError)
            return null;
        if (response.Records.Answers.Length > 0)
            return null;

        var question = request.Questions[0];
        var promoted = response.Records.Authorities
            .Where(r => RecordIsExactTypeOrCoveringSig(r, question.Name, question.Type))
            .ToImmutableArray();
        if (!promoted.Any(r => r.Type == question.Type))
            return null;

        return response with
        {
            Records = response.Records with
            {
                Answers = promoted,
                Authorities = response.Records.Authorities
                    .Where(r => !RecordIsExactTypeOrCoveringSig(r, question.Name, question.Type))
                    .ToImmutableArray()
            }
        };
    }

    private static bool RecordIsExactTypeOrCoveringSig(
        DomainResourceRecord record,
        DomainLabels qname,
        DomainRecordType type)
    {
        if (!record.Name.Equals(qname))
            return false;
        if (record.Type == type)
            return true;
        return record.Type is DomainRecordType.RRSIG &&
               record.Data is ResourceRecordSignatureData sig &&
               sig.TypeCovered == type;
    }

    private static DomainMessage CoalesceCoveringRrsigsIntoAnswers(DomainMessage response)
    {
        var covered = new HashSet<(string Name, DomainRecordType Type)>();
        foreach (var record in response.Records.Answers)
        {
            if (record.Type is DomainRecordType.RRSIG or DomainRecordType.OPT)
                continue;
            covered.Add((record.Name.ToString(), record.Type));
        }

        if (covered.Count == 0)
            return response;

        var extra = response.Records.Authorities
            .Concat(response.Records.Additional)
            .Where(r =>
                r.Type is DomainRecordType.RRSIG &&
                r.Data is ResourceRecordSignatureData sig &&
                covered.Contains((r.Name.ToString(), sig.TypeCovered)))
            .ToImmutableArray();
        if (extra.Length == 0)
            return response;

        return response with
        {
            Records = response.Records with
            {
                Answers = response.Records.Answers.AddRange(extra)
            }
        };
    }

    /// <summary>
    /// Completed recursive answers are not TLD referrals: drop parent NS/NSEC(3)
    /// from AUTHORITY, keep same-owner SOA, keep NS glue, clear AA.
    /// </summary>
    private static DomainMessage StripParentDelegationProof(DomainMessage request, DomainMessage response)
    {
        var flags = response.Flags with { Authoritative = false };
        if (response.Records.Answers.Length == 0)
            return response with { Id = request.Id, Flags = flags };

        response = CoalesceCoveringRrsigsIntoAnswers(response);

        var qname = request.Questions[0].Name;
        var nsTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var record in response.Records.Answers)
        {
            if (record.Type is DomainRecordType.NS && record.Data is NameData nameData)
                nsTargets.Add(nameData.Name.ToString());
        }

        var authorities = response.Records.Authorities
            .Where(r => r.Type is DomainRecordType.SOA && r.Name.Equals(qname))
            .ToImmutableArray();
        var additional = response.Records.Additional
            .Where(r =>
                r.Type is DomainRecordType.OPT ||
                (r.Type is DomainRecordType.A or DomainRecordType.AAAA &&
                 nsTargets.Contains(r.Name.ToString())))
            .ToImmutableArray();

        return response with
        {
            Id = request.Id,
            Flags = flags,
            Records = response.Records with
            {
                Authorities = authorities,
                Additional = additional
            }
        };
    }

    private static DomainMessage ServFail(DomainMessage request)
        => DomainMessage.CreateResponse(request, DomainResourceRecords.Empty, DomainResponseCode.ServerFailure);

    private static bool IsUnresolvedReferral(DomainMessage message)
    {
        if (message.Records.Answers.Length != 0)
            return false;
        if (message.Flags.ResponseCode is not DomainResponseCode.NoError)
            return false;
        // NODATA: SOA in authority. A referral has NS and no SOA.
        if (message.Records.Authorities.Any(static r => r.Type is DomainRecordType.SOA))
            return false;
        var qname = message.Questions.Length > 0 ? message.Questions[0].Name : DomainLabels.Empty;
        return GetNameserverNames(message.Records, qname).Any();
    }

    private async ValueTask<List<IPAddress>> ResolveNameserverAddressesAsync(
        DomainMessageContext parentContext,
        PooledList<string> nsNames,
        PooledList<IPEndPoint> endPoints,
        CancellationToken cancellationToken)
    {
        // Glue A/AAAA recursion shares DnssecScope with the client query. Its hop
        // outcomes must not Observe into Status (Bogus is sticky and SERVFAILs
        // unsigned final answers). Keys/DS learned along the way still apply.
        parentContext.DnssecScope?.PushIgnoreStatus();
        try
        {
            using var nameserverQueries = nsNames
                .SelectMany([SuppressMessage("ReSharper", "AccessToDisposedClosure")] (name) =>
                    new[]
                    {
                        _internalClient
                            .SendAsync(parentContext, DomainMessage.CreateRequest(name, DomainRecordType.A),
                                cancellationToken).AsTask(),
                        _internalClient
                            .SendAsync(parentContext, DomainMessage.CreateRequest(name, DomainRecordType.AAAA),
                                cancellationToken).AsTask()
                    })
                .Select(i => i.OperationCancelledToNull().ConvertExceptionsToNull())
                .ToPooledList();

            var responses = await Task.WhenAll(nameserverQueries);
            var nsNameSet = nsNames.ToHashSet(StringComparer.OrdinalIgnoreCase);
            var addresses = new List<IPAddress>();
            foreach (var nextMessage in responses)
            {
                if (nextMessage is null) continue;
                addresses.AddRange(GetGlueAddresses(nextMessage.Records, nsNameSet));
            }

            return addresses;
        }
        finally
        {
            parentContext.DnssecScope?.PopIgnoreStatus();
        }
    }

    private static IEnumerable<string> GetNameserverNames(
        IEnumerable<DomainResourceRecord> records,
        DomainLabels qname)
    {
        foreach (var record in records)
        {
            if (record.Type is not DomainRecordType.NS)
                continue;
            if (record.Data is not NameData nameData)
                continue;
            // Authority NS for a CNAME target (e.g. v.aaplimg.com on itunes.apple.com)
            // is not a zone cut for QNAME. Following it sends bag.itunes.apple.com to
            // GSLB nameservers that REFUSE the name; the parent still has the answer.
            if (!NsOwnerAppliesToQuery(record.Name, qname))
                continue;
            yield return nameData.Name.ToString();
        }
    }

    /// <summary>
    /// True when <paramref name="nsOwner"/> is QNAME or a parent of it.
    /// </summary>
    private static bool NsOwnerAppliesToQuery(DomainLabels nsOwner, DomainLabels qname)
    {
        if (nsOwner.Labels.Length == 0)
            return true;
        if (nsOwner.Labels.Length > qname.Labels.Length)
            return false;

        var offset = qname.Labels.Length - nsOwner.Labels.Length;
        for (var i = 0; i < nsOwner.Labels.Length; i++)
        {
            if (!nsOwner.Labels[i].Label.Equals(
                    qname.Labels[offset + i].Label, StringComparison.OrdinalIgnoreCase))
                return false;
        }

        return true;
    }

    private static IEnumerable<IPAddress> GetGlueAddresses(
        IEnumerable<DomainResourceRecord> records,
        HashSet<string> nsNames)
    {
        foreach (var record in records)
        {
            if (record.Type is not (DomainRecordType.A or DomainRecordType.AAAA))
                continue;
            if (!nsNames.Contains(record.Name.ToString()))
                continue;
            if (record.Data is not IPAddressData addressData)
                continue;
            yield return addressData.Address;
        }
    }

    public string Name { get; } = "Recursive Resolver";
    public int Priority { get; } = 5000;
}
