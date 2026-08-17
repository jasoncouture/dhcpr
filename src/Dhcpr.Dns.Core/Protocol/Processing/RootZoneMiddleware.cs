using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Protocol.Zone;
using Dhcpr.Dns.Core.RootZone;

using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// Answers from the primed root.zone snapshot (TLD NS/DS and in-zone glue) before
/// live upstream queries. Priority must be less than <see cref="UpstreamQueryMiddleware"/>.
/// </summary>
public sealed class RootZoneMiddleware : IDomainMessageMiddleware
{
    private readonly IRootZoneStore _store;
    private readonly IOptionsMonitor<DnsConfiguration> _options;

    public RootZoneMiddleware(IRootZoneStore store, IOptionsMonitor<DnsConfiguration> options)
    {
        _store = store;
        _options = options;
    }

    public string Name => "Root Zone";
    public int Priority => 50;

    public async ValueTask<DomainMessage?> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        await Task.Yield();
        // Directed upstream hops must hit live nameservers (with DO=1) so DNSSEC
        // sees RRSIGs. Primed root.zone answers are unsigned NS/DS/glue only.
        if (context.UpstreamEndpoints is { Length: > 0 })
            return null;

        var snapshot = _store.Current;
        if (snapshot is null)
            return null;

        var question = context.DomainMessage.Questions[0];
        var ownerKey = RootZoneSnapshot.NormalizeOwner(question.Name.ToString());
        if (!snapshot.TryGetRecords(ownerKey, out var records))
            return null;

        var matching = records.Where(r => r.Type == question.Type).ToImmutableArray();
        if (matching.Length == 0)
            return null;

        var rrsigs = records
            .Where(r =>
                r.Type is DomainRecordType.RRSIG &&
                r.Data is ResourceRecordSignatureData sig &&
                sig.TypeCovered == question.Type)
            .ToImmutableArray();

        // When DNSSEC validation is on, primed answers must carry currently-valid RRSIGs.
        // Stale root.zone between Internic refreshes (SOA refresh 1800s, RRSIG calendar
        // windows) otherwise verifies Bogus → systemic SERVFAIL → probe restarts.
        var dnssecEnabled = _options.CurrentValue.Dnssec?.Enabled ?? true;
        if (dnssecEnabled)
        {
            if (rrsigs.Length == 0 || !HasCurrentlyValidRrsig(rrsigs, DateTimeOffset.UtcNow))
                return null;
        }

        var answers = rrsigs.Length == 0
            ? matching
            : matching.Concat(rrsigs).ToImmutableArray();

        var additional = question.Type is DomainRecordType.NS
            ? CollectGlue(snapshot, matching)
            : ImmutableArray<DomainResourceRecord>.Empty;

        var response = DomainMessage.CreateResponse(
            context.DomainMessage,
            answers: answers,
            authorities: null,
            additional: additional,
            responseCode: DomainResponseCode.NoError);

        response = response with
        {
            Flags = response.Flags with
            {
                Authoritative = true,
                RecursionAvailable = true
            }
        };

        return response;
    }

    private static bool HasCurrentlyValidRrsig(
        ImmutableArray<DomainResourceRecord> rrsigs,
        DateTimeOffset utcNow)
    {
        var nowUnix = (uint)utcNow.ToUnixTimeSeconds();
        foreach (var record in rrsigs)
        {
            if (record.Data is not ResourceRecordSignatureData sig)
                continue;
            if (nowUnix >= sig.SignatureInception && nowUnix <= sig.SignatureExpiration)
                return true;
        }

        return false;
    }

    private static ImmutableArray<DomainResourceRecord> CollectGlue(
        RootZoneSnapshot snapshot,
        ImmutableArray<DomainResourceRecord> nsRecords)
    {
        var glue = ImmutableArray.CreateBuilder<DomainResourceRecord>();
        foreach (var ns in nsRecords)
        {
            if (ns.Data is not NameData nameData)
                continue;
            var key = RootZoneSnapshot.NormalizeOwner(nameData.Name.ToString());
            if (!snapshot.TryGetRecords(key, out var hostRecords))
                continue;
            foreach (var record in hostRecords)
            {
                if (record.Type is DomainRecordType.A or DomainRecordType.AAAA)
                    glue.Add(record);
            }
        }

        return glue.ToImmutable();
    }
}
