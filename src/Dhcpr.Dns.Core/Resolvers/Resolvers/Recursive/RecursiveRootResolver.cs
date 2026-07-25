using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Net;

using Dhcpr.Core;
using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

public sealed class RecursiveRootResolver : IDomainMessageMiddleware, IDisposable
{
    private const int MaxParallelNameservers = 3;

    private readonly IInternalDomainClient _internalClient;
    private readonly ILogger<RecursiveRootResolver> _logger;
    private DnsConfiguration _configuration;
    private readonly IDisposable? _subscription;

    public RecursiveRootResolver(
        IOptionsMonitor<DnsConfiguration> configuration,
        IInternalDomainClient internalClient,
        ILogger<RecursiveRootResolver> logger
    )
    {
        _configuration = configuration.CurrentValue;
        _subscription = configuration.OnChange(c => _configuration = c);
        _internalClient = internalClient;
        _logger = logger;
    }

    private IPEndPoint[] GetBestRoute(DomainLabels name)
    {
        var routes = _configuration.GetParsedRoutes();
        for (var i = 0; i < name.Labels.Length; i++)
        {
            var suffix = string.Join(".", name.Labels.Skip(i).Select(l => l.Label));
            if (routes.TryGetValue(suffix, out var endpoints))
                return endpoints;
        }

        if (routes.TryGetValue(".", out var defaultEndpoints))
            return defaultEndpoints;

        return Array.Empty<IPEndPoint>();
    }

    public async ValueTask<DomainMessage?> ProcessAsync(DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        // Directed upstream hops are owned by UpstreamQueryMiddleware.
        if (context.UpstreamEndpoints is { Length: > 0 })
            return null;

        var question = context.DomainMessage.Questions[0];
        var remainingLabels = question.Name.Labels;
        using var endPoints = ListPool<IPEndPoint>.Default.Get();
        
        // Find best matching route
        var routeAddresses = GetBestRoute(question.Name);
        endPoints.AddRange(routeAddresses);
        
        using var zoneLabels = ListPool<DomainLabel>.Default.Get();
        using var addressRecords = ListPool<IPAddress>.Default.Get();
        try
        {
            // Descend label by label looking for zone cuts. For A/AAAA/CNAME we do not NS-probe
            // the leaf itself — parent nameservers are enough to answer the final QTYPE.
            while (remainingLabels.Length > 0)
            {
                addressRecords.Clear();
                var next = remainingLabels[^1];
                remainingLabels = remainingLabels[..^1];
                zoneLabels.Insert(0, next);

                if (remainingLabels.Length == 0 &&
                    question.Type is not DomainRecordType.NS)
                {
                    break;
                }

                var nsMessage = DomainMessage.CreateRequest(
                    new DomainLabels(zoneLabels.ToImmutableArray()),
                    DomainRecordType.NS);

                var targetMessage = DomainMessage.CreateRequest(
                    question.Name,
                    question.Type);

                var nsTask = QueryUpstreamAsync(context, nsMessage, endPoints, cancellationToken).AsTask();
                var targetTask = QueryUpstreamAsync(context, targetMessage, endPoints, cancellationToken).AsTask();
                await Task.WhenAll(nsTask, targetTask);

                var targetResponse = await targetTask;
                if (targetResponse.Records.Answers.Length > 0 ||
                    (targetResponse.Flags.Authoritative &&
                     targetResponse.Flags.ResponseCode == DomainResponseCode.NameError))
                {
                    return targetResponse with { Id = context.DomainMessage.Id };
                }

                var responseMessage = await nsTask;
                using var nsNames = GetNameserverNames(responseMessage.Records).ToPooledList();

                // Authoritative NODATA / no referral — keep current nameservers and continue.
                if (nsNames.Count == 0)
                    continue;

                var nsNameSet = nsNames.ToHashSet(StringComparer.OrdinalIgnoreCase);
                addressRecords.AddRange(GetGlueAddresses(responseMessage.Records, nsNameSet));

                if (addressRecords.Count == 0)
                    addressRecords.AddRange(
                        await ResolveNameserverAddressesAsync(context, nsNames, endPoints, cancellationToken));

                // Could not resolve NS addresses — keep current endpoints.
                if (addressRecords.Count == 0)
                    continue;

                endPoints.Clear();
                endPoints.AddRange(addressRecords.Select(i => new IPEndPoint(i, 53)));
            }

            var clonedRequest = context.DomainMessage with { Id = (ushort)Random.Shared.Next(0, ushort.MaxValue + 1) };
            var result = await QueryFollowingReferralsAsync(context, clonedRequest, endPoints, cancellationToken);

            if (result.Records.Answers.Length != 0 ||
                clonedRequest.Questions[0].Type is not (DomainRecordType.A or DomainRecordType.AAAA))
            {
                return FinalizeRecursiveResponse(context.DomainMessage, result);
            }

            clonedRequest = clonedRequest with
            {
                Questions = clonedRequest.Questions.Select(x => x with { Type = DomainRecordType.CNAME })
                    .ToImmutableArray()
            };
            var cnameResponse =
                await QueryFollowingReferralsAsync(context, clonedRequest, endPoints, cancellationToken);
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
            .Take(MaxParallelNameservers)
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

            if (last.Records.Answers.Length > 0)
                return last;

            using var nsNames = GetNameserverNames(last.Records).ToPooledList();
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

            endPoints.Clear();
            endPoints.AddRange(referralAddresses.Select(i => new IPEndPoint(i, 53)));
        }

        return IsUnresolvedReferral(last!) ? ServFail(request) : last!;
    }

    private static DomainMessage FinalizeRecursiveResponse(DomainMessage request, DomainMessage response)
        => IsUnresolvedReferral(response) ? ServFail(request) : response with { Id = request.Id };

    private static DomainMessage ServFail(DomainMessage request)
        => DomainMessage.CreateResponse(request, DomainResourceRecords.Empty, DomainResponseCode.ServerFailure);

    private static bool IsUnresolvedReferral(DomainMessage message)
        => message.Records.Answers.Length == 0
           && message.Flags.ResponseCode is DomainResponseCode.NoError
           && message.Records.Any(r => r.Type is DomainRecordType.NS);

    private async ValueTask<List<IPAddress>> ResolveNameserverAddressesAsync(
        DomainMessageContext parentContext,
        PooledList<string> nsNames,
        PooledList<IPEndPoint> endPoints,
        CancellationToken cancellationToken)
    {
        // We only want to query upstream if the nameserver is in-bailiwick.
        // If it's out-of-bailiwick, we MUST do a full recursive lookup from the root.
        // Otherwise, we end up querying the current nameservers for a domain they don't own,
        // and they will return REFUSED or NXDOMAIN.
        
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
        var addresses = new List<IPAddress>();
        foreach (var nextMessage in responses)
        {
            if (nextMessage is null) continue;
            addresses.AddRange(nextMessage.Records
                .Where(i => i.Type is DomainRecordType.A or DomainRecordType.AAAA)
                .Select(i => ((IPAddressData)i.Data).Address));
        }

        return addresses;
    }

    private static IEnumerable<string> GetNameserverNames(IEnumerable<DomainResourceRecord> records)
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

    public void Dispose()
    {
        _subscription?.Dispose();
    }
}
