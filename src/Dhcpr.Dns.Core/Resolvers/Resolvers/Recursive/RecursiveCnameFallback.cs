using System.Collections.Immutable;
using System.Net;

using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

/// <summary>
/// Re-queries QTYPE CNAME when a recursive A/AAAA walk returned no answers.
/// The caller still finalizes so the original question type is kept.
/// </summary>
public static class RecursiveCnameFallback
{
    public static async ValueTask<DomainMessage> TryQueryAsync(
        DomainMessageContext context,
        DomainMessage request,
        DomainMessage originalResult,
        PooledList<IPEndPoint> endPoints,
        IReferralWalker walker,
        CancellationToken cancellationToken)
    {
        var cnameRequest = request with
        {
            Questions = request.Questions
                .Select(x => x with { Type = DomainRecordType.CNAME })
                .ToImmutableArray()
        };
        var cnameResponse = await walker.FollowAsync(
            context, cnameRequest, endPoints, cancellationToken);
        if (cnameResponse.Records.Answers.Length > 0 &&
            cnameResponse.Flags.ResponseCode is DomainResponseCode.NoError)
            return cnameResponse;

        return originalResult;
    }
}
