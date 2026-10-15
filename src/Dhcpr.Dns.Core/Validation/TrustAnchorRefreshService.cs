using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.RootZone;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core.Validation;

/// <summary>
/// RFC 5011 probe of the root DNSKEY RRset. Queries the root servers directly:
/// the validating resolver SERVFAILs when the trust anchor is already stale, and
/// that is the failure this probe exists to avoid on the next rollover.
/// </summary>
public sealed partial class TrustAnchorRefreshService : BackgroundService
{
    /// <summary>RFC 5011 §2.3: query no more often than hourly and at least every 15 days.</summary>
    internal static readonly TimeSpan SuccessInterval = TimeSpan.FromDays(1);

    internal static readonly TimeSpan RetryInterval = TimeSpan.FromHours(1);
    private static readonly TimeSpan ProbeTimeout = TimeSpan.FromSeconds(3);

    private readonly ITrustAnchorStore _anchors;
    private readonly IRootServerTips _tips;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly TimeProvider _time;
    private readonly ILogger<TrustAnchorRefreshService> _logger;

    public TrustAnchorRefreshService(
        ITrustAnchorStore anchors,
        IRootServerTips tips,
        IServiceScopeFactory scopeFactory,
        TimeProvider time,
        ILogger<TrustAnchorRefreshService> logger)
    {
        _anchors = anchors;
        _tips = tips;
        _scopeFactory = scopeFactory;
        _time = time;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            var delay = await ProbeOnceAsync(stoppingToken).ConfigureAwait(false);
            try
            {
                await Task.Delay(delay, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }

    internal async Task<TimeSpan> ProbeOnceAsync(CancellationToken cancellationToken)
    {
        var endpoints = _tips.GetEndpoints();
        if (endpoints.Length == 0)
        {
            LogRootTipsNotReady(_logger);
            return TimeSpan.FromSeconds(30);
        }

        try
        {
            await using var scope = _scopeFactory.CreateAsyncScope();
            var clients = scope.ServiceProvider.GetRequiredService<IDomainClientFactory>();
            var edns = scope.ServiceProvider.GetRequiredService<IEdnsProtocolService>();
            var crypto = scope.ServiceProvider.GetRequiredService<IDnssecValidator>();
            var loopTag = scope.ServiceProvider.GetRequiredService<IEdnsLoopTag>();

            var request = DomainMessage.CreateRequest(
                DomainLabels.Empty,
                DomainRecordType.DNSKEY,
                recursionRequested: false);
            request = DirectedQueryEdns.AddOptRecordWithDoBit(request, edns, loopTag.Create(request));

            using var client = await clients.GetParallelDomainClientAsync(
                endpoints.Select(endpoint => new DomainClientOptions
                {
                    EndPoint = endpoint,
                    Type = DomainClientType.Udp,
                    TimeOut = ProbeTimeout
                }),
                cancellationToken).ConfigureAwait(false);

            var response = await client.SendAsync(request, cancellationToken).ConfigureAwait(false);
            if (response.Flags.ResponseCode is not DomainResponseCode.NoError)
            {
                LogProbeFailed(_logger, response.Flags.ResponseCode);
                return RetryInterval;
            }

            var dnsKeys = response.Records.Answers
                .Where(static record => record.Type is DomainRecordType.DNSKEY && record.Name.Count == 0)
                .ToList();
            var rrsigs = DnssecRrsetVerifier.FindCoveringRrsigs(
                response.Records.Answers
                    .Concat(response.Records.Authorities)
                    .Concat(response.Records.Additional),
                DomainLabels.Empty,
                DomainRecordType.DNSKEY);

            var outcome = await _anchors.AcceptDnsKeySetAsync(
                dnsKeys,
                rrsigs,
                crypto,
                _time.GetUtcNow(),
                cancellationToken).ConfigureAwait(false);

            if (outcome.Kind == TrustAnchorRefreshKind.NotAuthenticated)
            {
                LogDnsKeyNotAuthenticated(_logger);
                return RetryInterval;
            }

            foreach (var trustAnchorEvent in outcome.Events)
                LogTrustAnchorEvent(_logger, trustAnchorEvent.Kind, trustAnchorEvent.KeyTag);

            if (outcome.Kind == TrustAnchorRefreshKind.Updated)
                LogTrustAnchorsUpdated(_logger, outcome.Events.Count);

            return SuccessInterval;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogProbeThrew(_logger, ex);
            return RetryInterval;
        }
    }

    [LoggerMessage(Level = LogLevel.Debug, Message = "Root tips not ready; delaying trust-anchor probe")]
    private static partial void LogRootTipsNotReady(ILogger logger);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Root DNSKEY probe returned {ResponseCode}")]
    private static partial void LogProbeFailed(ILogger logger, DomainResponseCode responseCode);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Root DNSKEY RRset did not validate against the current trust anchors")]
    private static partial void LogDnsKeyNotAuthenticated(ILogger logger);

    [LoggerMessage(Level = LogLevel.Information, Message = "Trust anchor {Kind} for key tag {KeyTag}")]
    private static partial void LogTrustAnchorEvent(ILogger logger, TrustAnchorEventKind kind, ushort keyTag);

    [LoggerMessage(Level = LogLevel.Information, Message = "Updated root trust anchors ({Events} event(s))")]
    private static partial void LogTrustAnchorsUpdated(ILogger logger, int events);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Root DNSKEY probe failed")]
    private static partial void LogProbeThrew(ILogger logger, Exception exception);
}
