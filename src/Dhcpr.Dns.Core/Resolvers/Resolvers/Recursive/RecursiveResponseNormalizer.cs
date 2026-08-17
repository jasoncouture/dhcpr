using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

public static class RecursiveResponseNormalizer
{
    public static DomainMessage FinalizeRecursiveResponse(DomainMessage request, DomainMessage response)
    {
        if (TryPromoteAuthoritativeAnswer(request, response) is { } promoted)
            response = promoted;
        if (IsUnresolvedReferral(response))
            return ServFail(request);
        return StripParentDelegationProof(request, response);
    }

    /// <summary>
    /// Move an AA child's QTYPE RRset (plus covering RRSIGs) from AUTHORITY to
    /// ANSWER. Parent referrals are AA=0 and must be followed, not copied.
    /// </summary>
    public static DomainMessage? TryPromoteAuthoritativeAnswer(DomainMessage request, DomainMessage response)
    {
        if (!response.Flags.Authoritative)
            return null;
        if (request.Questions.Length == 0)
            return null;
        if (response.Flags.ResponseCode is not DomainResponseCode.NoError)
            return null;
        if (response.Records.Answers.Length > 0)
            return null;

        var question = request.Questions[0];
        var promoted = response.Records.Authorities
            .Where(r => RecordIsExactTypeOrCoveringSig(r, question.Name, question.Type))
            .ToImmutableArray();
        if (!promoted.Any(r => r.Type == question.Type))
            return null;

        return response with
        {
            Records = response.Records with
            {
                Answers = promoted,
                Authorities = response.Records.Authorities
                    .Where(r => !RecordIsExactTypeOrCoveringSig(r, question.Name, question.Type))
                    .ToImmutableArray()
            }
        };
    }

    public static DomainMessage ServFail(DomainMessage request)
        => DomainMessage.CreateResponse(request, DomainResourceRecords.Empty, DomainResponseCode.ServerFailure);

    public static bool IsUnresolvedReferral(DomainMessage message)
    {
        if (message.Records.Answers.Length != 0)
            return false;
        if (message.Flags.ResponseCode is not DomainResponseCode.NoError)
            return false;
        // NODATA: SOA in authority. A referral has NS and no SOA.
        if (message.Records.Authorities.Any(static r => r.Type is DomainRecordType.SOA))
            return false;
        var qname = message.Questions.Length > 0 ? message.Questions[0].Name : DomainLabels.Empty;
        return GetNameserverNames(message.Records, qname).Any();
    }

    public static IEnumerable<string> GetNameserverNames(
        IEnumerable<DomainResourceRecord> records,
        DomainLabels qname)
    {
        foreach (var record in records)
        {
            if (record.Type is not DomainRecordType.NS)
                continue;
            if (record.Data is not NameData nameData)
                continue;
            // Authority NS for a CNAME target (e.g. v.aaplimg.com on itunes.apple.com)
            // is not a zone cut for QNAME. Following it sends bag.itunes.apple.com to
            // GSLB nameservers that REFUSE the name; the parent still has the answer.
            if (!NsOwnerAppliesToQuery(record.Name, qname))
                continue;
            yield return nameData.Name.ToString();
        }
    }

    /// <summary>
    /// True when <paramref name="nsOwner"/> is QNAME or a parent of it.
    /// </summary>
    public static bool NsOwnerAppliesToQuery(DomainLabels nsOwner, DomainLabels qname)
    {
        if (nsOwner.Labels.Length == 0)
            return true;
        if (nsOwner.Labels.Length > qname.Labels.Length)
            return false;

        var offset = qname.Labels.Length - nsOwner.Labels.Length;
        for (var i = 0; i < nsOwner.Labels.Length; i++)
        {
            if (!nsOwner.Labels[i].Label.Equals(
                    qname.Labels[offset + i].Label, StringComparison.OrdinalIgnoreCase))
                return false;
        }

        return true;
    }

    private static bool RecordIsExactTypeOrCoveringSig(
        DomainResourceRecord record,
        DomainLabels qname,
        DomainRecordType type)
    {
        if (!record.Name.Equals(qname))
            return false;
        if (record.Type == type)
            return true;
        return record.Type is DomainRecordType.RRSIG &&
               record.Data is ResourceRecordSignatureData sig &&
               sig.TypeCovered == type;
    }

    private static DomainMessage CoalesceCoveringRrsigsIntoAnswers(DomainMessage response)
    {
        var covered = new HashSet<(string Name, DomainRecordType Type)>();
        foreach (var record in response.Records.Answers)
        {
            if (record.Type is DomainRecordType.RRSIG or DomainRecordType.OPT)
                continue;
            covered.Add((record.Name.ToString(), record.Type));
        }

        if (covered.Count == 0)
            return response;

        var extra = response.Records.Authorities
            .Concat(response.Records.Additional)
            .Where(r =>
                r.Type is DomainRecordType.RRSIG &&
                r.Data is ResourceRecordSignatureData sig &&
                covered.Contains((r.Name.ToString(), sig.TypeCovered)))
            .ToImmutableArray();
        if (extra.Length == 0)
            return response;

        return response with
        {
            Records = response.Records with
            {
                Answers = response.Records.Answers.AddRange(extra)
            }
        };
    }

    /// <summary>
    /// Completed recursive answers are not TLD referrals: drop parent NS/NSEC(3)
    /// from AUTHORITY, keep same-owner SOA, keep NS glue, clear AA.
    /// </summary>
    private static DomainMessage StripParentDelegationProof(DomainMessage request, DomainMessage response)
    {
        var flags = response.Flags with { Authoritative = false };
        if (response.Records.Answers.Length == 0)
            return response with { Id = request.Id, Questions = request.Questions, Flags = flags };

        response = CoalesceCoveringRrsigsIntoAnswers(response);

        var qname = request.Questions[0].Name;
        var nsTargets = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var record in response.Records.Answers)
        {
            if (record.Type is DomainRecordType.NS && record.Data is NameData nameData)
                nsTargets.Add(nameData.Name.ToString());
        }

        var authorities = response.Records.Authorities
            .Where(r => r.Type is DomainRecordType.SOA && r.Name.Equals(qname))
            .ToImmutableArray();
        var additional = response.Records.Additional
            .Where(r =>
                r.Type is DomainRecordType.OPT ||
                (r.Type is DomainRecordType.A or DomainRecordType.AAAA &&
                 nsTargets.Contains(r.Name.ToString())))
            .ToImmutableArray();

        return response with
        {
            Id = request.Id,
            Questions = request.Questions,
            Flags = flags,
            Records = response.Records with
            {
                Authorities = authorities,
                Additional = additional
            }
        };
    }
}
