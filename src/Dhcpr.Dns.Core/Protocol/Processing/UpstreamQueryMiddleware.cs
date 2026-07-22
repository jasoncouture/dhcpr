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

        using var pooled = endPoints.ToPooledList();
        var client = await _clientFactory.GetParallelDomainClient(
            SelectQueryEndpoints(pooled),
            cancellationToken);

        var queryMessage = AddOptRecordWithDoBit(context.DomainMessage, _ednsProtocolService);
        return await client.SendAsync(queryMessage, cancellationToken);
    }

    private static DomainMessage AddOptRecordWithDoBit(DomainMessage message, IEdnsProtocolService ednsProtocolService)
    {
        var existingOpt = message.Records.Additional.FirstOrDefault(r => r.Type == DomainRecordType.OPT);
        var optRecord = existingOpt is not null
            ? ednsProtocolService.CreateOptRecord(4096, dnssecOk: true,
                extendedRCode: ednsProtocolService.GetExtendedRCode(existingOpt),
                version: ednsProtocolService.GetEdnsVersion(existingOpt),
                optData: existingOpt.Data as RecordData.OptData)
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

    private static IEnumerable<DomainClientOptions> SelectQueryEndpoints(PooledList<IPEndPoint> endPoints)
    {
        IEnumerable<IPEndPoint> selected = endPoints.Count <= MaxParallelNameservers
            ? endPoints
            : endPoints.OrderBy(_ => Random.Shared.Next()).Take(MaxParallelNameservers);

        return selected.Select(i => new DomainClientOptions { EndPoint = i, Type = DomainClientType.Udp })
            .ToArray();
    }
}
