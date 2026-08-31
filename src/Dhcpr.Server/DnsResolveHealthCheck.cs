using System.Collections.Concurrent;

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

    private static async Task<string?> ValidateRequestAsync(IDnsQueryExecutor executor, DomainMessage query,
        CancellationToken cancellationToken)
    {
        var response = await executor.QueryAsync(query, cancellationToken);
        
        if (response is null)
        {
            return "no response";
        }
                

        if (response.Flags.ResponseCode is not DomainResponseCode.NoError and not DomainResponseCode.NameError)
        {
            return $"rcode={response.Flags.ResponseCode}";
        }

        if (!response.Records.Answers.Any(static r =>
                r.Type is DomainRecordType.A or DomainRecordType.AAAA or DomainRecordType.CNAME))
        {
            return "no address/CNAME answer";
        }

        return null;
    }

    public async Task<HealthCheckResult> CheckHealthAsync(
        HealthCheckContext context,
        CancellationToken cancellationToken)
    {
        var config = _options.CurrentValue.HealthCheck ?? new DnsHealthCheckConfiguration();
        if (!config.Enabled)
            return HealthCheckResult.Healthy("DNS health check disabled");

        if (config.Domains is not { Length: > 0 })
            return HealthCheckResult.Healthy("No DNS health-check domains configured");

        using var timeoutTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeoutTokenSource.CancelAfter(TimeSpan.FromSeconds(config.TimeoutSeconds));
        var timeoutCancellationToken = timeoutTokenSource.Token;

        var failures = new ConcurrentBag<(string Domain, string Reason)>();

        await Task.WhenAll(config.Domains.Select(async domain =>
        {
            var name = domain.Trim().TrimEnd('.');
            try
            {
                var request = DomainMessage.CreateRequest(name, DomainRecordType.A);
                var aErrorMessage = await ValidateRequestAsync(_executor, request, timeoutCancellationToken);
                request = DomainMessage.CreateRequest(name, DomainRecordType.AAAA);
                var aaaaErrorMessage = await ValidateRequestAsync(_executor, request, timeoutCancellationToken);
                if (aErrorMessage is not null && aaaaErrorMessage is not null)
                {
                    failures.Add((name, aErrorMessage));
                    failures.Add((name, aaaaErrorMessage));
                }
            }
            catch (OperationCanceledException) when (timeoutCancellationToken.IsCancellationRequested)
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
