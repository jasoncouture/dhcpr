using System.Collections.Immutable;
using System.Diagnostics.CodeAnalysis;
using System.Net;

using Dhcpr.Core;
using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Protocol.Zone;

namespace Dhcpr.Dns.Core.Authoritative;

/// <summary>
/// Follows in-zone NS cuts from a loaded parent, preferring a loaded child zone
/// at the cut when present.
/// </summary>
public sealed class AuthoritativeNsCutMiddleware : IDomainMessageMiddleware
{
    private readonly AuthoritativeZoneStore _zones;
    private readonly IInternalDomainClient _internalClient;

    public AuthoritativeNsCutMiddleware(
        AuthoritativeZoneStore zones,
        IInternalDomainClient internalClient)
    {
        _zones = zones;
        _internalClient = internalClient;
    }

    public string Name => "Authoritative NS Cut";
    // After local auth (300), before forward (500) / recursive (5000).
    public int Priority => 310;

    public async ValueTask<DomainMessage?> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        if (context.UpstreamEndpoints is { Length: > 0 })
            return null;

        if (context.DomainMessage.Questions.Length == 0)
            return null;

        var question = context.DomainMessage.Questions[0];
        if (_zones.FindZone(question.Name.ToString()) is not { } localZone)
            return null;

        var local = ZoneAnswerEngine.Answer(localZone, context.DomainMessage);
        if (local.Kind is not ZoneAnswerKind.Referral || local.Message is null)
            return null;

        using var endPoints = ListPool<IPEndPoint>.Default.Get();
        if (!await TrySeedEndpointsFromReferralAsync(
                context, local.Message, endPoints, cancellationToken).ConfigureAwait(false))
        {
            return ServFail(context.DomainMessage);
        }

        var clonedRequest = context.DomainMessage with
        {
            Id = (ushort)Random.Shared.Next(0, ushort.MaxValue + 1)
        };
        var followed = await QueryFollowingReferralsAsync(
            context, clonedRequest, endPoints, local.ReferralCutApex, cancellationToken)
            .ConfigureAwait(false);
        return Finalize(context.DomainMessage, followed);
    }

    private async ValueTask<DomainMessage> QueryFollowingReferralsAsync(
        DomainMessageContext parentContext,
        DomainMessage request,
        PooledList<IPEndPoint> endPoints,
        string? previousCutApex,
        CancellationToken cancellationToken)
    {
        const int maxReferralDepth = 8;
        DomainMessage? last = null;
        var lastCut = previousCutApex;

        for (var depth = 0; depth < maxReferralDepth; depth++)
        {
            if (lastCut is not null &&
                _zones.FindZoneExactApex(lastCut) is { } childZone)
            {
                var local = ZoneAnswerEngine.Answer(childZone, request);
                if (local.Message is not null &&
                    local.Kind is ZoneAnswerKind.Answer or ZoneAnswerKind.NoData or ZoneAnswerKind.NameError)
                {
                    parentContext.DoNotCacheResponse = true;
                    return local.Message;
                }

                if (local.Kind is ZoneAnswerKind.Referral && local.Message is not null)
                {
                    last = local.Message;
                    lastCut = local.ReferralCutApex;
                    if (!await TrySeedEndpointsFromReferralAsync(
                            parentContext, local.Message, endPoints, cancellationToken).ConfigureAwait(false))
                        return ServFail(request);
                    continue;
                }
            }

            last = await QueryUpstreamAsync(parentContext, request, endPoints, cancellationToken)
                .ConfigureAwait(false);

            if (last.Records.Answers.Length > 0)
                return last;

            if (last.Flags.ResponseCode is not DomainResponseCode.NoError)
                return last;

            using var nsNames = GetNameserverNames(last.Records).ToPooledList();
            if (nsNames.Count == 0)
                return last;

            lastCut = GetNsOwner(last.Records);

            var nsNameSet = nsNames.ToHashSet(StringComparer.OrdinalIgnoreCase);
            using var referralAddresses = GetGlueAddresses(last.Records, nsNameSet).ToPooledList();
            if (referralAddresses.Count == 0)
            {
                referralAddresses.AddRange(
                    await ResolveNameserverAddressesAsync(parentContext, nsNames, endPoints, cancellationToken)
                        .ConfigureAwait(false));
                if (referralAddresses.Count == 0)
                    return ServFail(request);
            }

            endPoints.Clear();
            endPoints.AddRange(referralAddresses.Select(i => new IPEndPoint(i, 53)));
        }

        return IsUnresolvedReferral(last!) ? ServFail(request) : last!;
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
        return await _internalClient.SendAsync(parentContext, message, upstream, cancellationToken)
            .ConfigureAwait(false);
    }

    private async ValueTask<bool> TrySeedEndpointsFromReferralAsync(
        DomainMessageContext parentContext,
        DomainMessage referral,
        PooledList<IPEndPoint> endPoints,
        CancellationToken cancellationToken)
    {
        using var nsNames = GetNameserverNames(referral.Records).ToPooledList();
        if (nsNames.Count == 0)
            return false;

        var nsNameSet = nsNames.ToHashSet(StringComparer.OrdinalIgnoreCase);
        using var addresses = GetGlueAddresses(referral.Records, nsNameSet).ToPooledList();
        if (addresses.Count == 0)
        {
            addresses.AddRange(
                await ResolveNameserverAddressesAsync(parentContext, nsNames, endPoints, cancellationToken)
                    .ConfigureAwait(false));
        }

        if (addresses.Count == 0)
            return false;

        endPoints.Clear();
        endPoints.AddRange(addresses.Select(i => new IPEndPoint(i, 53)));
        return true;
    }

    private async ValueTask<List<IPAddress>> ResolveNameserverAddressesAsync(
        DomainMessageContext parentContext,
        PooledList<string> nsNames,
        PooledList<IPEndPoint> endPoints,
        CancellationToken cancellationToken)
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

        var responses = await Task.WhenAll(nameserverQueries).ConfigureAwait(false);
        var nsNameSet = nsNames.ToHashSet(StringComparer.OrdinalIgnoreCase);
        var addresses = new List<IPAddress>();
        foreach (var nextMessage in responses)
        {
            if (nextMessage is null) continue;
            addresses.AddRange(GetGlueAddresses(nextMessage.Records, nsNameSet));
        }

        return addresses;
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

    private static DomainMessage Finalize(DomainMessage request, DomainMessage response)
        => IsUnresolvedReferral(response) ? ServFail(request) : response with { Id = request.Id };

    private static DomainMessage ServFail(DomainMessage request)
        => DomainMessage.CreateResponse(request, DomainResourceRecords.Empty, DomainResponseCode.ServerFailure);

    private static bool IsUnresolvedReferral(DomainMessage message)
        => message.Records.Answers.Length == 0
           && message.Flags.ResponseCode is DomainResponseCode.NoError
           && message.Records.Any(r => r.Type is DomainRecordType.NS);
}
