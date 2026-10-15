using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// Builds an outbound copy of a query with OPT/DO=1. Does not mutate the cache-key message.
/// </summary>
public static class DirectedQueryEdns
{
    public static DomainMessage AddOptRecordWithDoBit(
        DomainMessage message,
        IEdnsProtocolService ednsProtocolService,
        ImmutableArray<byte>? selfQueryCookie = null)
    {
        // Our OPT only. Do not forward the stub's COOKIE/NSID/etc. to nameservers.
        OptionData? optData = null;
        if (selfQueryCookie is { Length: > 0 } cookie)
        {
            optData = new OptionData(ImmutableArray.Create(
                new EdnsOption(EdnsLoopTag.OptionCode, cookie)));
        }

        var optRecord = ednsProtocolService.CreateOptRecord(4096, dnssecOk: true, optData: optData);

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
