using System.Collections.Immutable;
using System.Net;

using Dhcpr.Dns.Core.Authoritative;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.DynamicDns;

public static class DynamicDnsAnswerer
{
    public static DomainMessage? TryAnswer(
        DynamicDnsStore store,
        IAuthoritativeZoneStore zones,
        DomainMessage request)
    {
        if (request.Questions.Length == 0)
            return null;

        var question = request.Questions[0];
        if (question.Type is not (DomainRecordType.A or DomainRecordType.AAAA))
            return null;

        if (!store.TryGet(question.Name.ToString(), out var entry))
            return null;

        var ttl = store.Ttl;
        DomainResourceRecord? match = null;

        if (question.Type is DomainRecordType.A &&
            entry.Ipv4 is not null &&
            IPAddress.TryParse(entry.Ipv4, out var v4))
        {
            match = new DomainResourceRecord(
                question.Name,
                DomainRecordType.A,
                DomainRecordClass.IN,
                ttl,
                new IPAddressData(v4));
        }
        else if (question.Type is DomainRecordType.AAAA &&
                 entry.Ipv6 is not null &&
                 IPAddress.TryParse(entry.Ipv6, out var v6))
        {
            match = new DomainResourceRecord(
                question.Name,
                DomainRecordType.AAAA,
                DomainRecordClass.IN,
                ttl,
                new IPAddressData(v6));
        }

        if (match is not null)
        {
            return WithAa(request, [match], authorities: null, DomainResponseCode.NoError);
        }

        // Dynamically registered name, but not this address family → NODATA + SOA when possible.
        ImmutableArray<DomainResourceRecord>? authorities = null;
        if (zones.FindZone(question.Name.ToString()) is { } zone)
            authorities = [zone.SoaRecord];

        return WithAa(request, answers: null, authorities, DomainResponseCode.NoError);
    }

    private static DomainMessage WithAa(
        DomainMessage request,
        IEnumerable<DomainResourceRecord>? answers,
        IEnumerable<DomainResourceRecord>? authorities,
        DomainResponseCode code)
    {
        var response = DomainMessage.CreateResponse(request, answers, authorities, additional: null, code);
        return response with
        {
            Flags = response.Flags with
            {
                Authoritative = true,
                RecursionAvailable = true
            }
        };
    }
}
