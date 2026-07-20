using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Sockets;

using Dhcpr.Core;
using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

public sealed class RecursiveRootResolver : IDomainMessageMiddleware
{
    private const int MaxParallelNameservers = 3;

    private readonly IDomainClientFactory _clientFactory;
    private readonly ILogger<RecursiveRootResolver> _logger;
    private readonly ImmutableArray<IPEndPoint> _servers;

    public RecursiveRootResolver(
        IOptionsMonitor<RootServerConfiguration> rootServerConfiguration,
        IDomainClientFactory clientFactory,
        ILogger<RecursiveRootResolver> logger
    )
    {
        _servers = rootServerConfiguration.CurrentValue.Addresses
            .Select(i => i.GetEndPoint(53))
            .Cast<IPEndPoint>()
            .OrderBy(_ => Random.Shared.Next())
            .ToImmutableArray();
        _clientFactory = clientFactory;
        _logger = logger;
    }

    public async ValueTask<DomainMessage?> ProcessAsync(DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        var question = context.DomainMessage.Questions[0];
        var remainingLabels = question.Name.Labels;
        using var endPoints = ListPool<IPEndPoint>.Default.Get();
        endPoints.AddRange(_servers);
        using var zoneLabels = ListPool<DomainLabel>.Default.Get();
        using var addressRecords = ListPool<IPAddress>.Default.Get();
        try
        {
            // Walk every label including the QNAME. Non-zone cuts typically return NODATA/SOA
            // (no NS) and we keep the parent nameservers.
            while (remainingLabels.Length > 0)
            {
                addressRecords.Clear();
                var next = remainingLabels[^1];
                remainingLabels = remainingLabels[..^1];
                zoneLabels.Insert(0, next);

                var resolver = await _clientFactory.GetParallelDomainClient(
                    SelectQueryEndpoints(endPoints),
                    cancellationToken);
                var message = DomainMessage.CreateRequest(
                    new DomainLabels(zoneLabels.ToImmutableArray()),
                    DomainRecordType.NS);

                var responseMessage = await resolver.SendAsync(message, cancellationToken);
                using var nsNames = GetNameserverNames(responseMessage.Records).ToPooledList();

                // Authoritative NODATA / no referral — keep current nameservers and continue.
                if (nsNames.Count == 0)
                    continue;

                var nsNameSet = nsNames.ToHashSet(StringComparer.OrdinalIgnoreCase);
                addressRecords.AddRange(GetGlueAddresses(responseMessage.Records, nsNameSet));

                if (addressRecords.Count == 0)
                {
                    var internalClient =
                        await _clientFactory.GetDomainClient(
                            new DomainClientOptions() { Type = DomainClientType.Internal },
                            cancellationToken);

                    using var nameserverQueries = nsNames
                        .SelectMany([SuppressMessage("ReSharper", "AccessToDisposedClosure")] (name) =>
                            new[]
                            {
                                internalClient
                                    .SendAsync(DomainMessage.CreateRequest(name, DomainRecordType.A),
                                        cancellationToken).AsTask(),
                                internalClient
                                    .SendAsync(DomainMessage.CreateRequest(name, DomainRecordType.AAAA),
                                        cancellationToken).AsTask()
                            })
                        .Select(i => i.OperationCancelledToNull().ConvertExceptionsToNull())
                        .ToPooledList();

                    var responses = await Task.WhenAll(nameserverQueries);
                    foreach (var nextMessage in responses)
                    {
                        if (nextMessage is null) continue;
                        addressRecords.AddRange(nextMessage.Records
                            .Where(i => i.Type is DomainRecordType.A or DomainRecordType.AAAA)
                            .Select(i => ((IPAddressData)i.Data).Address));
                    }
                }

                // Could not resolve NS addresses — keep current endpoints.
                if (addressRecords.Count == 0)
                    continue;

                endPoints.Clear();
                endPoints.AddRange(addressRecords.Select(i => new IPEndPoint(i, 53)));
            }

            var clonedRequest = context.DomainMessage with { Id = (ushort)Random.Shared.Next(0, ushort.MaxValue + 1) };
            var result = await QueryFollowingReferralsAsync(clonedRequest, endPoints, cancellationToken);

            if (result.Records.Answers.Length != 0 ||
                clonedRequest.Questions[0].Type is not (DomainRecordType.A or DomainRecordType.AAAA))
            {
                return result;
            }

            clonedRequest = clonedRequest with
            {
                Questions = clonedRequest.Questions.Select(x => x with { Type = DomainRecordType.CNAME })
                    .ToImmutableArray()
            };
            var cnameResponse = await QueryFollowingReferralsAsync(clonedRequest, endPoints, cancellationToken);
            if (cnameResponse.Records.Answers.Length > 0 &&
                cnameResponse.Flags.ResponseCode is DomainResponseCode.NoError)
            {
                return cnameResponse;
            }

            return result;
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

    private async ValueTask<DomainMessage> QueryFollowingReferralsAsync(
        DomainMessage request,
        PooledList<IPEndPoint> endPoints,
        CancellationToken cancellationToken)
    {
        const int maxReferralDepth = 8;
        DomainMessage? last = null;

        for (var depth = 0; depth < maxReferralDepth; depth++)
        {
            var resolver = await _clientFactory.GetParallelDomainClient(
                SelectQueryEndpoints(endPoints),
                cancellationToken);
            last = await resolver.SendAsync(request, cancellationToken);

            if (last.Records.Answers.Length > 0)
                return last;

            using var nsNames = GetNameserverNames(last.Records).ToPooledList();
            if (nsNames.Count == 0)
                return last;

            var nsNameSet = nsNames.ToHashSet(StringComparer.OrdinalIgnoreCase);
            using var referralAddresses = GetGlueAddresses(last.Records, nsNameSet).ToPooledList();
            if (referralAddresses.Count == 0)
                return last;

            endPoints.Clear();
            endPoints.AddRange(referralAddresses.Select(i => new IPEndPoint(i, 53)));
        }

        return last!;
    }

    private static IEnumerable<DomainClientOptions> SelectQueryEndpoints(PooledList<IPEndPoint> endPoints)
    {
        // Prefer IPv4 — IPv6 blackholes often ignore CancelAfter and stall the whole query.
        var preferred = endPoints.Where(i => i.AddressFamily == AddressFamily.InterNetwork).ToPooledList();
        var pool = preferred.Count > 0 ? preferred : endPoints;
        try
        {
            IEnumerable<IPEndPoint> selected = pool.Count <= MaxParallelNameservers
                ? pool
                : pool.OrderBy(_ => Random.Shared.Next()).Take(MaxParallelNameservers);

            return selected.Select(i => new DomainClientOptions { EndPoint = i, Type = DomainClientType.Udp })
                .ToArray();
        }
        finally
        {
            if (!ReferenceEquals(preferred, endPoints))
                preferred.Dispose();
        }
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
}
