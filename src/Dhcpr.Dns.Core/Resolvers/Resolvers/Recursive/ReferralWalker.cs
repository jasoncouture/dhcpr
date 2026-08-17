using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Net;

using Dhcpr.Core;
using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Protocol.Zone;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

public sealed class ReferralWalker : IReferralWalker
{
    private readonly IInternalDomainClient _internalClient;

    public ReferralWalker(IInternalDomainClient internalClient)
    {
        _internalClient = internalClient;
    }

    public async ValueTask<DomainMessage> FollowAsync(
        DomainMessageContext context,
        DomainMessage request,
        PooledList<IPEndPoint> endPoints,
        CancellationToken cancellationToken,
        ReferralWalkOptions? options = null)
    {
        options ??= ReferralWalkOptions.Recursive;
        const int maxReferralDepth = 8;
        DomainMessage? last = null;
        var lastCut = options.InitialCutApex;

        for (var depth = 0; depth < maxReferralDepth; depth++)
        {
            if (options.TryLocalCut is not null)
            {
                var localCut = await options.TryLocalCut(lastCut, request, cancellationToken)
                    .ConfigureAwait(false);
                if (localCut is { Terminal: true })
                    return localCut.Message;

                if (localCut is { Terminal: false })
                {
                    last = localCut.Message;
                    lastCut = localCut.NextCutApex;
                    if (!await TrySeedEndpointsAsync(
                            context, localCut.Message, endPoints, cancellationToken, options)
                        .ConfigureAwait(false))
                        return RecursiveResponseNormalizer.ServFail(request);
                    continue;
                }
            }

            last = await QueryUpstreamAsync(context, request, endPoints, cancellationToken);

            if (options.StopOnAuthoritativeAnswersOnly)
            {
                // TLD servers often echo delegation NS in ANSWER for QTYPE NS without AA.
                // That is still a referral — the signed apex RRset is on the child.
                if (last.Flags.Authoritative && last.Records.Answers.Length > 0)
                    return last;
            }
            else if (last.Records.Answers.Length > 0)
            {
                return last;
            }

            if (options.PromoteAuthoritativeAnswer &&
                RecursiveResponseNormalizer.TryPromoteAuthoritativeAnswer(request, last) is { } promoted)
                return promoted;

            if (last.Flags.ResponseCode is not DomainResponseCode.NoError)
                return last;

            using var nsNames = CollectNameserverNames(last.Records, request, options).ToPooledList();
            if (nsNames.Count == 0)
                return last;

            if (options.TryLocalCut is not null)
                lastCut = GetNsOwner(last.Records);

            var nsNameSet = nsNames.ToHashSet(StringComparer.OrdinalIgnoreCase);
            using var referralAddresses = GetGlueAddresses(last.Records, nsNameSet).ToPooledList();
            if (referralAddresses.Count == 0)
            {
                referralAddresses.AddRange(
                    await ResolveNameserverAddressesAsync(
                        context, nsNames, cancellationToken, options.IgnoreGlueHopDnssecStatus));
                if (referralAddresses.Count == 0)
                    return RecursiveResponseNormalizer.ServFail(request);
            }

            if (options.DetectSelfReferral)
            {
                // Parent NODATA often repeats the current zone's NS in AUTHORITY.
                // Following those is a self-referral loop → SERVFAIL (cert-manager NS walk).
                var currentAddresses = endPoints.Select(static e => e.Address).ToHashSet();
                if (referralAddresses.All(currentAddresses.Contains))
                    return last;
            }

            endPoints.Clear();
            endPoints.AddRange(referralAddresses.Select(i => new IPEndPoint(i, 53)));
        }

        if (options.ServFailNonAuthoritativeApexTypes &&
            !last!.Flags.Authoritative &&
            request.Questions[0].Type is DomainRecordType.NS or DomainRecordType.SOA
                or DomainRecordType.DNSKEY)
            return RecursiveResponseNormalizer.ServFail(request);

        return IsUnresolvedReferral(last!, options)
            ? RecursiveResponseNormalizer.ServFail(request)
            : last!;
    }

    public async ValueTask<bool> TrySeedEndpointsAsync(
        DomainMessageContext context,
        DomainMessage referral,
        PooledList<IPEndPoint> endPoints,
        CancellationToken cancellationToken,
        ReferralWalkOptions? options = null)
    {
        options ??= ReferralWalkOptions.Recursive;
        using var nsNames = CollectNameserverNames(referral.Records, referral, options).ToPooledList();
        if (nsNames.Count == 0)
            return false;

        var nsNameSet = nsNames.ToHashSet(StringComparer.OrdinalIgnoreCase);
        using var addresses = GetGlueAddresses(referral.Records, nsNameSet).ToPooledList();
        if (addresses.Count == 0)
        {
            addresses.AddRange(
                await ResolveNameserverAddressesAsync(
                    context, nsNames, cancellationToken, options.IgnoreGlueHopDnssecStatus)
                    .ConfigureAwait(false));
        }

        if (addresses.Count == 0)
            return false;

        endPoints.Clear();
        endPoints.AddRange(addresses.Select(i => new IPEndPoint(i, 53)));
        return true;
    }

    public async ValueTask<IReadOnlyList<IPAddress>> ResolveNameserverAddressesAsync(
        DomainMessageContext context,
        IReadOnlyList<string> nsNames,
        CancellationToken cancellationToken,
        bool ignoreDnssecStatus = true)
    {
        // Glue A/AAAA recursion shares DnssecScope with the client query. Its hop
        // outcomes must not Observe into Status (Bogus is sticky and SERVFAILs
        // unsigned final answers). Keys/DS learned along the way still apply.
        if (ignoreDnssecStatus)
            context.DnssecScope?.PushIgnoreStatus();
        try
        {
            using var nameserverQueries = nsNames
                .SelectMany([SuppressMessage("ReSharper", "AccessToDisposedClosure")] (name) =>
                    new[]
                    {
                        _internalClient
                            .SendAsync(context, DomainMessage.CreateRequest(name, DomainRecordType.A),
                                cancellationToken).AsTask(),
                        _internalClient
                            .SendAsync(context, DomainMessage.CreateRequest(name, DomainRecordType.AAAA),
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
            if (ignoreDnssecStatus)
                context.DnssecScope?.PopIgnoreStatus();
        }
    }

    public IEnumerable<string> GetNameserverNames(IEnumerable<DomainResourceRecord> records)
    {
        foreach (var record in records)
        {
            if (record.Type is not DomainRecordType.NS)
                continue;
            if (record.Data is not NameData nameData)
                continue;
            yield return nameData.Name.ToString();
        }
    }

    public IEnumerable<string> GetNameserverNames(
        IEnumerable<DomainResourceRecord> records,
        DomainLabels qname)
        => RecursiveResponseNormalizer.GetNameserverNames(records, qname);

    public IEnumerable<IPAddress> GetGlueAddresses(
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

    private IEnumerable<string> CollectNameserverNames(
        IEnumerable<DomainResourceRecord> records,
        DomainMessage request,
        ReferralWalkOptions options)
        => options.FilterNsOwnerByQname && request.Questions.Length > 0
            ? GetNameserverNames(records, request.Questions[0].Name)
            : GetNameserverNames(records);

    private static bool IsUnresolvedReferral(DomainMessage message, ReferralWalkOptions options)
    {
        if (options.UseRecursiveUnresolvedReferral)
            return RecursiveResponseNormalizer.IsUnresolvedReferral(message);

        return message.Records.Answers.Length == 0
               && message.Flags.ResponseCode is DomainResponseCode.NoError
               && message.Records.Any(r => r.Type is DomainRecordType.NS);
    }

    private static string? GetNsOwner(IEnumerable<DomainResourceRecord> records)
    {
        foreach (var record in records)
        {
            if (record.Type is DomainRecordType.NS)
                return RootZoneSnapshot.NormalizeOwner(record.Name.ToString());
        }

        return null;
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
}
