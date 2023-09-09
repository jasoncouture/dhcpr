using Dhcpr.Core;
using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Resolvers.Caching;

using DNS.Client.RequestResolver;
using DNS.Protocol;
using DNS.Protocol.ResourceRecords;

namespace Dhcpr.Dns.Core.Resolvers;

public sealed class DnsOutputFilter : IDnsOutputFilter
{
    public async Task<IResponse> UpdateResponse(IRequestResolver resolver, IRequest request, IResponse? response,
        CancellationToken cancellationToken)
    {
        if (response is null)
        {
            response = Response.FromRequest(request);
            response.ResponseCode = ResponseCode.ServerFailure;
            return response;
        }

        using var records = response.ToResourceRecordPooledList();


        // Some servers use shortened names, and when we return it directly, it confuses clients.
        // So doing a deep clone re-creates those records without the shortened names.
        response = response.Clone(deep: true);

        if (request.RecursionDesired &&
            request.Questions[0].Type is RecordType.CNAME or RecordType.A or RecordType.AAAA &&
            response.AnswerRecords.Any(i => i.Type == RecordType.CNAME) &&
            !response.AnswerRecords.Any(i => i.Type is RecordType.A or RecordType.AAAA))
        {
            response = new Response(response);
            var nameStack = new Stack<CanonicalNameResourceRecord>();
            using var canonicalNames = response.AnswerRecords.OfType<CanonicalNameResourceRecord>().ToPooledList();
            foreach (var cname in canonicalNames)
            {
                nameStack.Push(cname);
            }

            var visited = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            while (nameStack.TryPop(out var cname))
            {
                if (!visited.Add(cname.Name.ToString()!))
                    continue;
                foreach (var question in new[]
                         {
                             new Question(new Domain(cname.CanonicalDomainName.ToString()),
                                 request.Questions[0].Type, RecordClass.ANY)
                         })
                {
                    var innerRequest = new Request() { RecursionDesired = true, Questions = { question } };

                    var innerResponse = await resolver.Resolve(innerRequest, cancellationToken);
                    using var innerRecords = innerResponse.ToResourceRecordPooledList();
                    foreach (
                        var innerCanonicalNameResourceRecord in innerResponse.AnswerRecords
                            .OfType<CanonicalNameResourceRecord>()
                    )
                    {
                        nameStack.Push(innerCanonicalNameResourceRecord);
                        response.AnswerRecords.Add(innerCanonicalNameResourceRecord);
                    }

                    foreach (var answer in innerResponse.AnswerRecords.OfType<IPAddressResourceRecord>())
                    {
                        response.AnswerRecords.Add(answer);
                    }
                }
            }
        }

        using var secondPassRecords = response.ToResourceRecordPooledList();
        if (request.RecursionDesired &&
            secondPassRecords.All(i => i.Type != request.Questions[0].Type && i.Type != RecordType.CNAME))
        {
            response = Response.FromRequest(request);
            response.ResponseCode = ResponseCode.NameError;
            return response;
        }

        using var allAddressRecords = response.AnswerRecords.OfType<IPAddressResourceRecord>().ToPooledList();
        using var deduplicatedIpAddressResourceRecords = response.AnswerRecords.OfType<IPAddressResourceRecord>()
            .DistinctBy(i => (i.IPAddress, i.Name, i.Type)).ToPooledList();
        if (allAddressRecords.Count != deduplicatedIpAddressResourceRecords.Count)
        {
            foreach (var address in allAddressRecords)
                response.AnswerRecords.Remove(address);

            foreach (var address in deduplicatedIpAddressResourceRecords)
                response.AnswerRecords.Add(address);
        }


        OrderResourceRecords(response);

        if (response.Id != request.Id)
            response.Id = request.Id;

        return response;
    }

    private static void OrderResourceRecords(IResponse response)
    {
        OrderResourceRecords(response.AnswerRecords);
        OrderResourceRecords(response.AdditionalRecords);
        OrderResourceRecords(response.AuthorityRecords);
    }

    // This function will shuffle IP records,  
    private static void OrderResourceRecords(IList<IResourceRecord> records)
    {
        // No point in wasting time here, there's no addresses to shuffle.
        using var ipRecords = records.OfType<IPAddressResourceRecord>().ToPooledList();
        if (ipRecords.Count < 2) return;

        using var otherRecords = records.Where(i => i is not IPAddressResourceRecord)
            .ToPooledList();
        records.Clear();

        foreach (
            var addressRecord in ipRecords
                .OrderBy(i => i.IPAddress.IsInLocalSubnet() ? 0 : 1)
                .ThenShuffle()
        )
            records.Add(addressRecord.Clone());

        foreach (
            var otherRecord in otherRecords
        )
            records.Add(otherRecord);
    }
}