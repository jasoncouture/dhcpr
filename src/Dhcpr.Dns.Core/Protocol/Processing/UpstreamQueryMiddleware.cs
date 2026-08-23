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
    // Dual-stack NS plus amazonaws/ELB liars: a batch of 3 often has no honest
    // peer, so the next batch waits out a 250ms UDP timeout. 8 fits a typical
    // 4-name × A/AAAA cut in one race; first NOERROR wins.
    private const int MaxParallelNameservers = 8;

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

        // Caller shuffles; interleave families so one batch is not all IPv6.
        using var remaining = NameserverSelection.InterleaveFamilies(endPoints).ToPooledList();

        var queryMessage = DirectedQueryEdns.AddOptRecordWithDoBit(context.DomainMessage, _ednsProtocolService);
        DomainMessage? nameErrorFallback = null;

        while (remaining.Count > 0)
        {
            var batchCount = Math.Min(MaxParallelNameservers, remaining.Count);
            using var batch = ListPool<IPEndPoint>.Default.Get();
            for (var i = 0; i < batchCount; i++)
            {
                batch.Add(remaining[0]);
                remaining.RemoveAt(0);
            }

            using var client = await _clientFactory.GetParallelDomainClientAsync(
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

                // Don't trust NXDOMAIN from a partial peer set — some NS lie AA NXDOMAIN
                // for names delegated to other zones (seen on amazonaws.com / ELB).
                if (result.Flags.ResponseCode is DomainResponseCode.NameError)
                {
                    nameErrorFallback = result;
                    if (remaining.Count > 0)
                        continue;
                    return result;
                }

                return result;
            }
            catch (Exception ex) when (NameserverSelection.IsTransportFailure(ex))
            {
                // ENETUNREACH / host unreachable / etc. — skip this batch, try remaining peers.
            }
        }

        if (nameErrorFallback is not null)
            return nameErrorFallback;

        // Every nameserver endpoint failed.
        context.ServFailReason = "all upstream nameservers failed";
        return DomainMessage.CreateResponse(
            context.DomainMessage,
            DomainResourceRecords.Empty,
            DomainResponseCode.ServerFailure);
    }
}
