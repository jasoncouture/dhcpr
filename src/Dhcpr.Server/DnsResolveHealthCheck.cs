using System.Collections.Concurrent;
using System.Net;

using Dhcpr.Dns.Core;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace Dhcpr.Server;

/// <summary>
/// Resolves each configured domain through the DNS pipeline. Any failure → Unhealthy.
/// </summary>
public sealed class DnsResolveHealthCheck : IHealthCheck
{
    public const string Name = "dns_resolve";

    private readonly IDnsQueryExecutor _executor;
    private readonly IOptionsMonitor<DnsConfiguration> _options;

    public DnsResolveHealthCheck(
        IDnsQueryExecutor executor,
        IOptionsMonitor<DnsConfiguration> options)
    {
        _executor = executor;
        _options = options;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken = default)
    {
        var config = _options.CurrentValue.HealthCheck ?? new DnsHealthCheckConfiguration();
        if (!config.Enabled)
            return HealthCheckResult.Healthy("DNS health check disabled");

        if (config.Domains is not { Length: > 0 })
            return HealthCheckResult.Healthy("No DNS health-check domains configured");

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutCts.CancelAfter(TimeSpan.FromSeconds(config.TimeoutSeconds));
        var token = timeoutCts.Token;

        var failures = new ConcurrentBag<(string Domain, string Reason)>();

        await Task.WhenAll(config.Domains.Select(async domain =>
        {
            var name = domain.Trim().TrimEnd('.');
            try
            {
                var request = DomainMessage.CreateRequest(name, DomainRecordType.A);
                var response = await _executor.QueryAsync(request, token).ConfigureAwait(false);
                if (response is null)
                {
                    failures.Add((name, "no response"));
                    return;
                }

                if (response.Flags.ResponseCode is not DomainResponseCode.NoError)
                {
                    failures.Add((name, $"rcode={response.Flags.ResponseCode}"));
                    return;
                }

                if (!response.Records.Answers.Any(static r =>
                        r.Type is DomainRecordType.A or DomainRecordType.AAAA or DomainRecordType.CNAME))
                {
                    failures.Add((name, "no address/CNAME answer"));
                }
            }
            catch (OperationCanceledException) when (token.IsCancellationRequested)
            {
                failures.Add((name, cancellationToken.IsCancellationRequested ? "cancelled" : "timeout"));
            }
            catch (Exception ex)
            {
                failures.Add((name, ex.GetType().Name));
            }
        })).ConfigureAwait(false);

        if (failures.IsEmpty)
        {
            return HealthCheckResult.Healthy(
                $"Resolved {config.Domains.Length} domain(s)",
                data: new Dictionary<string, object>
                {
                    ["domains"] = config.Domains
                });
        }

        var detail = string.Join("; ", failures.Select(f => $"{f.Domain}: {f.Reason}"));
        return HealthCheckResult.Unhealthy(
            $"Failed {failures.Count}/{config.Domains.Length}: {detail}",
            data: new Dictionary<string, object>
            {
                ["failures"] = failures.Select(f => $"{f.Domain}: {f.Reason}").ToArray()
            });
    }
}
