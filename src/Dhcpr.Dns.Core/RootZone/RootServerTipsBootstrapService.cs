using System.Net;

using Dhcpr.Core;
using Dhcpr.Dns.Core.Protocol.Zone;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.RootZone;

/// <summary>
/// Ensures root tip IPs exist: prefer config Addresses; otherwise load/fetch named.root
/// (IP mirrors allowed — DNS may not work yet).
/// </summary>
public sealed class RootServerTipsBootstrapService : IHostedService
{
    private readonly RootServerTips _tips;
    private readonly IOptionsMonitor<RootServerConfiguration> _options;
    private readonly IOptionsMonitor<ApplicationConfiguration> _application;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<RootServerTipsBootstrapService> _logger;

    public RootServerTipsBootstrapService(
        RootServerTips tips,
        IOptionsMonitor<RootServerConfiguration> options,
        IOptionsMonitor<ApplicationConfiguration> application,
        IServiceScopeFactory scopeFactory,
        ILogger<RootServerTipsBootstrapService> logger)
    {
        _tips = tips;
        _options = options;
        _application = application;
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        if (_options.CurrentValue.Addresses.Length > 0)
        {
            _logger.LogInformation("Using {Count} configured root server addresses",
                _options.CurrentValue.Addresses.Length);
            return;
        }

        var cachePath = RootZonePaths.GetNamedRootCachePath(_application);
        if (File.Exists(cachePath))
        {
            try
            {
                var cached = await File.ReadAllTextAsync(cachePath, cancellationToken).ConfigureAwait(false);
                var fromCache = ParseTipCacheOrNamedRoot(cached);
                if (fromCache.Length > 0)
                {
                    _tips.SetDownloadedTips(fromCache);
                    _logger.LogInformation("Loaded {Count} root tips from {Path}", fromCache.Length, cachePath);
                    return;
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to load root tip cache from {Path}", cachePath);
            }
        }

        foreach (var url in RootZonePaths.NamedRootUrls)
        {
            try
            {
                await using var scope = _scopeFactory.CreateAsyncScope();
                var http = scope.ServiceProvider.GetRequiredService<NamedRootHttpClient>();
                using var response = await http.GetAsync(url, cancellationToken).ConfigureAwait(false);
                response.EnsureSuccessStatusCode();
                var text = await response.Content.ReadAsStringAsync(cancellationToken).ConfigureAwait(false);
                var addresses = ZoneFileParser.ParseNamedRootAddresses(text);
                if (addresses.Length == 0)
                    continue;

                _tips.SetDownloadedTips(addresses);
                var tipLines = string.Join('\n', addresses.Select(static a => a.ToString()));
                await AtomicFileReplace.WriteAsync(cachePath, $"{tipLines}\n", cancellationToken)
                    .ConfigureAwait(false);
                _logger.LogInformation("Downloaded {Count} root tips from {Url}", addresses.Length, url);
                return;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to download named.root from {Url}", url);
            }
        }

        _logger.LogError("No root server tips available from config or named.root");
    }

    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;

    private static IPAddress[] ParseTipCacheOrNamedRoot(string text)
    {
        var addresses = new List<IPAddress>();
        foreach (var line in text.Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (line.StartsWith(';'))
                continue;
            if (IPAddress.TryParse(line, out var ip))
                addresses.Add(ip);
        }

        if (addresses.Count > 0)
            return addresses.Distinct().ToArray();

        return ZoneFileParser.ParseNamedRootAddresses(text).ToArray();
    }
}
