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

                // NXDOMAIN/SERVFAIL/REFUSED are not referrals, even if NS is present.
                if (responseMessage.Flags.ResponseCode is not DomainResponseCode.NoError)
                    continue;

                using var nsNames = RecursiveResponseNormalizer.GetNameserverNames(
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
                return RecursiveResponseNormalizer.FinalizeRecursiveResponse(context.DomainMessage, result);
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
                return RecursiveResponseNormalizer.FinalizeRecursiveResponse(context.DomainMessage, cnameResponse);
            }

            return RecursiveResponseNormalizer.FinalizeRecursiveResponse(context.DomainMessage, result);
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

            if (RecursiveResponseNormalizer.TryPromoteAuthoritativeAnswer(request, last) is { } promoted)
                return promoted;

            if (last.Flags.ResponseCode is not DomainResponseCode.NoError)
                return last;

            using var nsNames = RecursiveResponseNormalizer.GetNameserverNames(
                last.Records, request.Questions[0].Name).ToPooledList();
            if (nsNames.Count == 0)
                return last;

            var nsNameSet = nsNames.ToHashSet(StringComparer.OrdinalIgnoreCase);
            using var referralAddresses = GetGlueAddresses(last.Records, nsNameSet).ToPooledList();
            if (referralAddresses.Count == 0)
            {
                referralAddresses.AddRange(
                    await ResolveNameserverAddressesAsync(parentContext, nsNames, endPoints, cancellationToken));
                if (referralAddresses.Count == 0)
                    return RecursiveResponseNormalizer.ServFail(request);
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
            return RecursiveResponseNormalizer.ServFail(request);

        return RecursiveResponseNormalizer.IsUnresolvedReferral(last)
            ? RecursiveResponseNormalizer.ServFail(request)
            : last!;
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
