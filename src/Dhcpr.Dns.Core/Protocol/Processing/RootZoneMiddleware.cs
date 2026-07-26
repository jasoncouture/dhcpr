using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Protocol.Zone;
using Dhcpr.Dns.Core.RootZone;

namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// Answers from the primed root.zone snapshot (TLD NS/DS and in-zone glue) before
/// live upstream queries. Priority must be less than <see cref="UpstreamQueryMiddleware"/>.
/// </summary>
public sealed class RootZoneMiddleware : IDomainMessageMiddleware
{
    private readonly IRootZoneStore _store;

    public RootZoneMiddleware(IRootZoneStore store)
    {
        _store = store;
    }

    public string Name => "Root Zone";
    public int Priority => 50;

    public ValueTask<DomainMessage?> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        var snapshot = _store.Current;
        if (snapshot is null)
            return ValueTask.FromResult<DomainMessage?>(null);

        var question = context.DomainMessage.Questions[0];
        var ownerKey = RootZoneSnapshot.NormalizeOwner(question.Name.ToString());
        if (!snapshot.TryGetRecords(ownerKey, out var records))
            return ValueTask.FromResult<DomainMessage?>(null);

        var matching = records.Where(r => r.Type == question.Type).ToImmutableArray();
        if (matching.Length == 0)
            return ValueTask.FromResult<DomainMessage?>(null);

        var additional = question.Type is DomainRecordType.NS
            ? CollectGlue(snapshot, matching)
            : ImmutableArray<DomainResourceRecord>.Empty;

        var response = DomainMessage.CreateResponse(
            context.DomainMessage,
            answers: matching,
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

        return ValueTask.FromResult<DomainMessage?>(response);
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
