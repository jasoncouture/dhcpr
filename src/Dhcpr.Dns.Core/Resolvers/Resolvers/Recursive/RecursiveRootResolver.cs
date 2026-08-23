using System.Collections.Immutable;
using System.Net;

using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.Zone;
using Dhcpr.Dns.Core.RootZone;

using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

public sealed partial class RecursiveRootResolver : IDomainMessageMiddleware
{
    private readonly IInternalDomainClient _internalClient;
    private readonly ILogger<RecursiveRootResolver> _logger;
    private readonly IReferralWalker _referralWalker;
    private readonly IRootServerTips _rootServerTips;

    public RecursiveRootResolver(
        IRootServerTips rootServerTips,
        IInternalDomainClient internalClient,
        IReferralWalker referralWalker,
        ILogger<RecursiveRootResolver> logger
    )
    {
        _rootServerTips = rootServerTips;
        _internalClient = internalClient;
        _referralWalker = referralWalker;
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
        using var zoneLabels = ListPool<DomainLabel>.Default.Get();
        if (context.NameserverTips is { } tips &&
            tips.TryGetClosest(question.Name, out var cachedTips, out var cachedZone))
        {
            rootEndPoints.AddRange(cachedTips);
            foreach (var label in cachedZone.Labels)
                zoneLabels.Add(label);
            remainingLabels = remainingLabels[..^cachedZone.Labels.Length];
        }
        else
        {
            rootEndPoints.AddRange(_rootServerTips.GetEndpoints().OrderBy(_ => Random.Shared.Next()));
        }

        using var addressRecords = ListPool<IPAddress>.Default.Get();
        try
        {
            // Descend label by label looking for zone cuts. Do not probe the leaf —
            // parent nameservers refer, then the referral walker asks the
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

                // NXDOMAIN/SERVFAIL/REFUSED are not referrals. Empty non-terminals
                // (Netflix internal.dradis…) are AA NXDOMAIN; deeper labels are not
                // cuts. FollowAsync from the current NS finds the leaf.
                if (responseMessage.Flags.ResponseCode is not DomainResponseCode.NoError)
                    break;

                using var nsNames = _referralWalker.GetNameserverNames(
                    responseMessage.Records, message.Questions[0].Name).ToPooledList();

                // Authoritative NODATA / no referral — no cut; stop walking labels.
                if (nsNames.Count == 0)
                    break;

                var nsNameSet = nsNames.ToHashSet(StringComparer.OrdinalIgnoreCase);
                addressRecords.AddRange(_referralWalker.GetGlueAddresses(responseMessage.Records, nsNameSet));

                if (addressRecords.Count == 0)
                    addressRecords.AddRange(
                        await _referralWalker.ResolveNameserverAddressesAsync(context, nsNames, cancellationToken));

                // Could not resolve NS addresses — keep current endpoints.
                if (addressRecords.Count == 0)
                    continue;

                rootEndPoints.Clear();
                rootEndPoints.AddRange(addressRecords.Select(i => new IPEndPoint(i, 53)));
                context.NameserverTips?.Remember(
                    new DomainLabels(zoneLabels.ToImmutableArray()).ToString(),
                    rootEndPoints);
            }

            var cloned = context.DomainMessage with { Id = (ushort)Random.Shared.Next(0, ushort.MaxValue + 1) };
            var result = await _referralWalker.FollowAsync(
                context, cloned, rootEndPoints, cancellationToken);

            if (result.Records.Answers.Length == 0 &&
                cloned.Questions[0].Type is DomainRecordType.A or DomainRecordType.AAAA)
            {
                result = await RecursiveCnameFallback.TryQueryAsync(
                    context, cloned, result, rootEndPoints, _referralWalker, cancellationToken);
            }

            return RecursiveResponseNormalizer.FinalizeRecursiveResponse(context.DomainMessage, result);
        }
        catch (Exception ex)
        {
            if (!cancellationToken.IsCancellationRequested)
            {
                LogUnhandledException(_logger, ex);
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

    public string Name { get; } = "Recursive Resolver";
    public int Priority { get; } = 5000;

    [LoggerMessage(Level = LogLevel.Error, Message = "An unhandled exception occurred while resolving recursively.")]
    private static partial void LogUnhandledException(ILogger logger, Exception exception);
}
