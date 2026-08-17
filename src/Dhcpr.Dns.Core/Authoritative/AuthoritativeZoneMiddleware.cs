using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.Authoritative;

/// <summary>
/// Answers from loaded authoritative zones (AA / NODATA / NXDOMAIN).
/// NS-cut follow is <see cref="AuthoritativeNsCutMiddleware"/>.
/// </summary>
public sealed class AuthoritativeZoneMiddleware : IDomainMessageMiddleware
{
    private readonly IAuthoritativeZoneStore _zones;

    public AuthoritativeZoneMiddleware(IAuthoritativeZoneStore zones)
    {
        _zones = zones;
    }

    public string Name => "Authoritative Zones";
    // After DynDNS (200), before NS-cut (310) / forward (500) / recursive (5000).
    public int Priority => 300;

    public async ValueTask<DomainMessage?> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        await Task.Yield();
        if (context.UpstreamEndpoints is { Length: > 0 })
            return null;

        if (context.DomainMessage.Questions.Length == 0)
            return null;

        var question = context.DomainMessage.Questions[0];
        if (_zones.FindZone(question.Name.ToString()) is not { } localZone)
            return null;

        var local = ZoneAnswerEngine.Answer(localZone, context.DomainMessage);
        if (local.Message is not null &&
            local.Kind is ZoneAnswerKind.Answer or ZoneAnswerKind.NoData or ZoneAnswerKind.NameError)
        {
            context.DoNotCacheResponse = true;
            return Finalize(context.DomainMessage, local.Message);
        }

        return null;
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
