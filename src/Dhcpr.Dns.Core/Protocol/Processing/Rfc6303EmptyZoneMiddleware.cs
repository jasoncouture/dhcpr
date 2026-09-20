using Dhcpr.Dns.Core.Authoritative;
using Dhcpr.Dns.Core.Protocol.RecordData;

using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// Serves RFC 6303 empty reverse zones locally so private PTR lookups are
/// NXDOMAIN instead of a leaked SERVFAIL. Lives inside the response cache;
/// the suffix match runs once per name.
/// </summary>
public sealed class Rfc6303EmptyZoneMiddleware : IDomainMessageMiddleware
{
    private static readonly TimeSpan Ttl = TimeSpan.FromSeconds(10800);
    private static readonly DomainLabels Localhost = new("localhost");
    private static readonly DomainLabels NobodyInvalid = new("nobody.invalid");

    private readonly IDomainMessageMiddleware _inner;
    private readonly IAuthoritativeZoneStore _zones;
    private readonly IOptionsMonitor<DnsConfiguration> _options;

    public Rfc6303EmptyZoneMiddleware(
        IDomainMessageMiddleware inner,
        IAuthoritativeZoneStore zones,
        IOptionsMonitor<DnsConfiguration> options)
    {
        _inner = inner;
        _zones = zones;
        _options = options;
    }

    public string Name => _inner.Name;
    public int Priority => _inner.Priority;

    public async ValueTask<DomainMessage> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        if (context.DomainMessage.Questions.IsDefaultOrEmpty)
            return await _inner.ProcessAsync(context, cancellationToken);

        var question = context.DomainMessage.Questions[0];
        if (!Rfc6303EmptyZones.TryMatch(question.Name, out var zoneName, out var isApex))
            return await _inner.ProcessAsync(context, cancellationToken);

        if (HasLocalOverride(question.Name, context))
            return await _inner.ProcessAsync(context, cancellationToken);

        context.AnsweredBy = "rfc6303";

        var apex = new DomainLabels(zoneName);
        var response = isApex
            ? AnswerApex(context.DomainMessage, apex, question.Type)
            : NxDomain(context.DomainMessage, apex);

        return response with
        {
            Flags = response.Flags with
            {
                Authoritative = true,
                RecursionAvailable = true
            }
        };
    }

    private bool HasLocalOverride(DomainLabels name, DomainMessageContext context)
    {
        if (_zones.FindZone(name.ToString()) is not null)
            return true;

        if (_options.CurrentValue.GetParsedRecords()
                .TryAnswer(context.DomainMessage, context.ClientEndPoint?.Address) is not null)
            return true;

        var routes = _options.CurrentValue.GetParsedRoutes();
        if (routes.Count == 0)
            return false;

        for (var i = 0; i < name.Labels.Length; i++)
        {
            var suffix = string.Join(".", name.Labels.Skip(i).Select(static l => l.Label));
            if (suffix is ".")
                continue;
            if (routes.TryGetValue(suffix, out var route) &&
                route.AllowsClient(context.ClientEndPoint?.Address))
                return true;
        }

        return false;
    }

    private static DomainMessage AnswerApex(DomainMessage request, DomainLabels apex, DomainRecordType type)
    {
        if (type is DomainRecordType.SOA)
            return DomainMessage.CreateResponse(request, answers: [Soa(apex)], responseCode: DomainResponseCode.NoError);
        if (type is DomainRecordType.NS)
            return DomainMessage.CreateResponse(request, answers: [Ns(apex)], responseCode: DomainResponseCode.NoError);

        return DomainMessage.CreateResponse(
            request,
            authorities: [Soa(apex)],
            responseCode: DomainResponseCode.NoError);
    }

    private static DomainMessage NxDomain(DomainMessage request, DomainLabels apex)
        => DomainMessage.CreateResponse(
            request,
            authorities: [Soa(apex)],
            responseCode: DomainResponseCode.NameError);

    private static DomainResourceRecord Soa(DomainLabels apex)
        => new(
            apex,
            DomainRecordType.SOA,
            DomainRecordClass.IN,
            Ttl,
            new StartOfAuthorityData(
                Localhost,
                NobodyInvalid,
                1,
                TimeSpan.FromHours(1),
                TimeSpan.FromMinutes(20),
                TimeSpan.FromDays(7),
                Ttl));

    private static DomainResourceRecord Ns(DomainLabels apex)
        => new(apex, DomainRecordType.NS, DomainRecordClass.IN, Ttl, new NameData(Localhost));
}
