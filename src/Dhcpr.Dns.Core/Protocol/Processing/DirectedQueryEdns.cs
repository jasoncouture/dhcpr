using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol;

namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// Builds an outbound copy of a query with OPT/DO=1. Does not mutate the cache-key message.
/// </summary>
public static class DirectedQueryEdns
{
    public static DomainMessage AddOptRecordWithDoBit(
        DomainMessage message,
        IEdnsProtocolService ednsProtocolService)
    {
        var existingOpt = message.Records.Additional.FirstOrDefault(r => r.Type == DomainRecordType.OPT);
        var optRecord = existingOpt is not null
            ? ednsProtocolService.CreateOptRecord(4096, dnssecOk: true,
                extendedRCode: ednsProtocolService.GetExtendedRCode(existingOpt),
                version: ednsProtocolService.GetEdnsVersion(existingOpt),
                optData: existingOpt.Data as RecordData.OptionData)
            : ednsProtocolService.CreateOptRecord(4096, dnssecOk: true);

        var newAdditional = message.Records.Additional
            .Where(r => r.Type != DomainRecordType.OPT)
            .Append(optRecord)
            .ToImmutableArray();

        return message with
        {
            Records = message.Records with { Additional = newAdditional }
        };
    }
}
