using System.Net;

using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.Authoritative;

/// <summary>
/// Follows in-zone NS cuts from a loaded parent, preferring a loaded child zone
/// at the cut when present.
/// </summary>
public sealed class AuthoritativeNsCutMiddleware : IDomainMessageMiddleware
{
    private readonly IAuthoritativeZoneStore _zones;
    private readonly IReferralWalker _referralWalker;

    public AuthoritativeNsCutMiddleware(
        IAuthoritativeZoneStore zones,
        IReferralWalker referralWalker)
    {
        _zones = zones;
        _referralWalker = referralWalker;
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

        var options = ReferralWalkOptions.Authoritative with
        {
            InitialCutApex = local.ReferralCutApex,
            TryLocalCut = (cutApex, request, cancellationToken) =>
                TryLocalChildZoneAsync(context, cutApex, request, cancellationToken)
        };

        using var endPoints = ListPool<IPEndPoint>.Default.Get();
        if (!await _referralWalker.TrySeedEndpointsAsync(
                context, local.Message, endPoints, cancellationToken, options).ConfigureAwait(false))
        {
            return ServFail(context.DomainMessage);
        }

        var clonedRequest = context.DomainMessage with
        {
            Id = (ushort)Random.Shared.Next(0, ushort.MaxValue + 1)
        };
        var followed = await _referralWalker.FollowAsync(
            context, clonedRequest, endPoints, cancellationToken, options)
            .ConfigureAwait(false);
        return Finalize(context.DomainMessage, followed);
    }

    private ValueTask<LocalReferralCut?> TryLocalChildZoneAsync(
        DomainMessageContext context,
        string? cutApex,
        DomainMessage request,
        CancellationToken cancellationToken)
    {
        _ = cancellationToken;
        if (cutApex is null || _zones.FindZoneExactApex(cutApex) is not { } childZone)
            return ValueTask.FromResult<LocalReferralCut?>(null);

        var local = ZoneAnswerEngine.Answer(childZone, request);
        if (local.Message is not null &&
            local.Kind is ZoneAnswerKind.Answer or ZoneAnswerKind.NoData or ZoneAnswerKind.NameError)
        {
            context.DoNotCacheResponse = true;
            return ValueTask.FromResult<LocalReferralCut?>(
                new LocalReferralCut(local.Message, Terminal: true, NextCutApex: null));
        }

        if (local.Kind is ZoneAnswerKind.Referral && local.Message is not null)
        {
            return ValueTask.FromResult<LocalReferralCut?>(
                new LocalReferralCut(local.Message, Terminal: false, local.ReferralCutApex));
        }

        return ValueTask.FromResult<LocalReferralCut?>(null);
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
