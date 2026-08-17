using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Protocol.Zone;

namespace Dhcpr.Dns.Core.Authoritative;

public static class ZoneAnswerEngine
{
    public static ZoneAnswerResult Answer(AuthoritativeZone zone, DomainMessage request)
    {
        if (request.Questions.Length == 0)
            return new ZoneAnswerResult(ZoneAnswerKind.NoMatch, null);

        var question = request.Questions[0];
        var qname = RootZoneSnapshot.NormalizeOwner(question.Name.ToString());
        if (!AuthoritativeZoneBuilder.IsUnderApex(qname, zone.Apex))
            return new ZoneAnswerResult(ZoneAnswerKind.NoMatch, null);

        var relative = AuthoritativeZoneBuilder.GetRelativeLabels(qname, zone.ApexLabels.ToArray());
        var current = zone.NameTree;

        for (var i = relative.Length - 1; i >= 0; i--)
        {
            var label = relative[i];
            if (!current.TryGetChild(label, out var next))
            {
                // Name does not exist at this label — wildcard or NXDOMAIN at closest encloser.
                return SynthesizeWildcardOrNxdomain(zone, request, question, current);
            }

            current = next;
            var labelsRemainingBelow = i; // indices 0..i-1 still to walk after this node
            if (current.HasNs && labelsRemainingBelow > 0)
            {
                // Strictly below an NS cut.
                return BuildReferral(zone, request, current);
            }
        }

        // Exact owner reached.
        return AnswerExact(zone, request, question, current);
    }

    private static ZoneAnswerResult AnswerExact(
        AuthoritativeZone zone,
        DomainMessage request,
        DomainQuestion question,
        ImmutableLabelTreeNode node)
    {
        var matching = node.Records.Where(r => r.Type == question.Type).ToImmutableArray();
        if (matching.Length > 0)
        {
            var additional = question.Type is DomainRecordType.NS
                ? CollectGlue(zone, matching)
                : ImmutableArray<DomainResourceRecord>.Empty;

            return new ZoneAnswerResult(
                ZoneAnswerKind.Answer,
                WithAa(request, matching, null, additional, DomainResponseCode.NoError, authoritative: true));
        }

        // RFC 1034 §3.6.2: a CNAME owner answers other QTYPEs with the CNAME.
        if (question.Type is not DomainRecordType.CNAME)
        {
            var cnames = node.Records.Where(r => r.Type is DomainRecordType.CNAME).ToImmutableArray();
            if (cnames.Length > 0)
            {
                return new ZoneAnswerResult(
                    ZoneAnswerKind.Answer,
                    WithAa(request, cnames, null, additional: null, DomainResponseCode.NoError, authoritative: true));
            }
        }

        // Exact name exists (RRs or empty non-terminal) → NODATA; wildcards suppressed.
        if (node.Records.Length > 0 || node.HasChildren)
        {
            return new ZoneAnswerResult(
                ZoneAnswerKind.NoData,
                WithAa(
                    request,
                    answers: null,
                    authorities: [zone.SoaRecord],
                    additional: null,
                    DomainResponseCode.NoError,
                    authoritative: true));
        }

        // Empty leaf with no RRs and no children — treat as NXDOMAIN (shouldn't normally appear).
        return new ZoneAnswerResult(
            ZoneAnswerKind.NameError,
            WithAa(
                request,
                answers: null,
                authorities: [zone.SoaRecord],
                additional: null,
                DomainResponseCode.NameError,
                authoritative: true));
    }

    private static ZoneAnswerResult SynthesizeWildcardOrNxdomain(
        AuthoritativeZone zone,
        DomainMessage request,
        DomainQuestion question,
        ImmutableLabelTreeNode closestEncloser)
    {
        if (closestEncloser.TryGetChild("*", out var wildcard))
        {
            var matching = wildcard.Records.Where(r => r.Type == question.Type).ToImmutableArray();
            if (matching.Length > 0)
            {
                var synthesized = matching
                    .Select(r => r with { Name = question.Name })
                    .ToImmutableArray();
                var additional = question.Type is DomainRecordType.NS
                    ? CollectGlue(zone, synthesized)
                    : ImmutableArray<DomainResourceRecord>.Empty;
                return new ZoneAnswerResult(
                    ZoneAnswerKind.Answer,
                    WithAa(request, synthesized, null, additional, DomainResponseCode.NoError, authoritative: true));
            }

            // Wildcard exists but not this type → NODATA
            return new ZoneAnswerResult(
                ZoneAnswerKind.NoData,
                WithAa(
                    request,
                    answers: null,
                    authorities: [zone.SoaRecord],
                    additional: null,
                    DomainResponseCode.NoError,
                    authoritative: true));
        }

        return new ZoneAnswerResult(
            ZoneAnswerKind.NameError,
            WithAa(
                request,
                answers: null,
                authorities: [zone.SoaRecord],
                additional: null,
                DomainResponseCode.NameError,
                authoritative: true));
    }

    private static ZoneAnswerResult BuildReferral(
        AuthoritativeZone zone,
        DomainMessage request,
        ImmutableLabelTreeNode cutNode)
    {
        var nsRecords = cutNode.Records.Where(r => r.Type is DomainRecordType.NS).ToImmutableArray();
        var glue = CollectGlue(zone, nsRecords);
        var cutOwner = nsRecords.Length > 0
            ? RootZoneSnapshot.NormalizeOwner(nsRecords[0].Name.ToString())
            : zone.Apex;

        return new ZoneAnswerResult(
            ZoneAnswerKind.Referral,
            WithAa(
                request,
                answers: null,
                authorities: nsRecords,
                additional: glue,
                DomainResponseCode.NoError,
                authoritative: false),
            ReferralCutApex: cutOwner);
    }

    private static ImmutableArray<DomainResourceRecord> CollectGlue(
        AuthoritativeZone zone,
        ImmutableArray<DomainResourceRecord> nsRecords)
    {
        var glue = ImmutableArray.CreateBuilder<DomainResourceRecord>();
        foreach (var ns in nsRecords)
        {
            if (ns.Data is not NameData nameData)
                continue;
            var host = RootZoneSnapshot.NormalizeOwner(nameData.Name.ToString());
            if (!AuthoritativeZoneBuilder.IsUnderApex(host, zone.Apex))
                continue;

            var relative = AuthoritativeZoneBuilder.GetRelativeLabels(host, zone.ApexLabels.ToArray());
            var node = zone.NameTree;
            var found = true;
            for (var i = relative.Length - 1; i >= 0; i--)
            {
                if (!node.TryGetChild(relative[i], out node!))
                {
                    found = false;
                    break;
                }
            }

            if (!found)
                continue;

            foreach (var record in node.Records)
            {
                if (record.Type is DomainRecordType.A or DomainRecordType.AAAA)
                    glue.Add(record);
            }
        }

        return glue.ToImmutable();
    }

    private static DomainMessage WithAa(
        DomainMessage request,
        IEnumerable<DomainResourceRecord>? answers,
        IEnumerable<DomainResourceRecord>? authorities,
        IEnumerable<DomainResourceRecord>? additional,
        DomainResponseCode code,
        bool authoritative)
    {
        var message = DomainMessage.CreateResponse(
            request,
            answers,
            authorities,
            additional,
            code);
        return message with
        {
            Flags = message.Flags with
            {
                Authoritative = authoritative,
                RecursionAvailable = true
            }
        };
    }
}
