using System.Collections.Immutable;
using System.Linq;
using System.Net;

using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Protocol;

namespace Dhcpr.Dns.Core.Protocol.Processing;

/// <summary>
/// Directed stub query to nameservers listed on <see cref="DomainMessageContext.UpstreamEndpoints"/>.
/// </summary>
public sealed class UpstreamQueryMiddleware : IDomainMessageMiddleware
{
    private const int MaxParallelNameservers = 3;

    private readonly IDomainClientFactory _clientFactory;
    private readonly IEdnsProtocolService _ednsProtocolService;

    public UpstreamQueryMiddleware(IDomainClientFactory clientFactory, IEdnsProtocolService ednsProtocolService)
    {
        _clientFactory = clientFactory;
        _ednsProtocolService = ednsProtocolService;
    }

    public string Name => "Upstream Query";
    public int Priority => 100;

    public async ValueTask<DomainMessage?> ProcessAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        if (context.UpstreamEndpoints is not { Length: > 0 } endPoints)
            return null;

        // Preserve caller order (RecursiveRootResolver shuffles before directing).
        using var remaining = endPoints.ToPooledList();

        var queryMessage = AddOptRecordWithDoBit(context.DomainMessage, _ednsProtocolService);

        while (remaining.Count > 0)
        {
            var batchCount = Math.Min(MaxParallelNameservers, remaining.Count);
            using var batch = ListPool<IPEndPoint>.Default.Get();
            for (var i = 0; i < batchCount; i++)
            {
                batch.Add(remaining[0]);
                remaining.RemoveAt(0);
            }

            using var client = await _clientFactory.GetParallelDomainClient(
                batch.Select(i => new DomainClientOptions { EndPoint = i, Type = DomainClientType.Udp }),
                cancellationToken);

            try
            {
                var result = await client.SendAsync(queryMessage, cancellationToken);
                // Empty SERVFAIL from a batch means "no usable peer response" — try others first.
                if (result.Flags.ResponseCode is DomainResponseCode.ServerFailure &&
                    result.Records.Answers.Length == 0 &&
                    remaining.Count > 0)
                    continue;

                return result;
            }
            catch (Exception ex) when (NameserverSelection.IsTransportFailure(ex))
            {
                // ENETUNREACH / host unreachable / etc. — skip this batch, try remaining peers.
            }
        }

        // Every nameserver endpoint failed.
        return DomainMessage.CreateResponse(
            context.DomainMessage,
            DomainResourceRecords.Empty,
            DomainResponseCode.ServerFailure);
    }

    private static DomainMessage AddOptRecordWithDoBit(DomainMessage message, IEdnsProtocolService ednsProtocolService)
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
