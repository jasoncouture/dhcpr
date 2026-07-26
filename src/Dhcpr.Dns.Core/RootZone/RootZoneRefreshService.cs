using Dhcpr.Dns.Core.Protocol.Zone;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.RootZone;

public sealed class RootZoneRefreshService : BackgroundService
{
    private readonly RootZoneStore _store;
    private readonly IRootServerTips _tips;
    private readonly IOptionsMonitor<RootServerConfiguration> _options;
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<RootZoneRefreshService> _logger;

    public RootZoneRefreshService(
        RootZoneStore store,
        IRootServerTips tips,
        IOptionsMonitor<RootServerConfiguration> options,
        IServiceScopeFactory scopeFactory,
        ILogger<RootZoneRefreshService> logger)
    {
        _store = store;
        _tips = tips;
        _options = options;
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await LoadFromDiskAsync(stoppingToken).ConfigureAwait(false);

        while (!stoppingToken.IsCancellationRequested)
        {
            var delay = await RefreshOnceAsync(stoppingToken).ConfigureAwait(false);
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

    /// <summary>Returns how long to wait before the next refresh attempt.</summary>
    internal async Task<TimeSpan> RefreshOnceAsync(CancellationToken cancellationToken)
    {
        if (_tips.GetEndpoints().Length == 0)
        {
            _logger.LogDebug("Root tips not ready; delaying root.zone fetch");
            return TimeSpan.FromSeconds(30);
        }

        var path = RootZonePaths.GetRootZonePath(_options);
        try
        {
            await using var scope = _scopeFactory.CreateAsyncScope();
            var http = scope.ServiceProvider.GetRequiredService<RootZoneHttpClient>();
            using var response = await http.GetRootZoneAsync(cancellationToken).ConfigureAwait(false);
            response.EnsureSuccessStatusCode();
            var bytes = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
            var text = System.Text.Encoding.UTF8.GetString(bytes);

            // Validate before replacing on-disk copy.
            var probe = ZoneFileParser.ParseRootZone(text, DateTimeOffset.UtcNow);
            if (probe.RecordsByOwner.Count < 2)
                throw new FormatException("Parsed root.zone looks empty");

            await AtomicFileReplace.WriteAsync(path, bytes, cancellationToken).ConfigureAwait(false);
            var loadedAt = new DateTimeOffset(File.GetLastWriteTimeUtc(path));
            var snapshot = ZoneFileParser.ParseRootZone(text, loadedAt);
            _store.Set(snapshot);

            _logger.LogInformation(
                "Loaded root.zone ({Count} owners, refresh={Refresh}s, expire={Expire}s)",
                snapshot.RecordsByOwner.Count,
                (int)snapshot.Soa.RefreshInterval.TotalSeconds,
                (int)snapshot.Soa.ExpireInterval.TotalSeconds);

            return snapshot.Soa.RefreshInterval;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "Failed to refresh root.zone from {Url}", RootZonePaths.RootZoneUrl);

            var current = _store.CurrentIgnoringExpiry;
            if (current is null)
            {
                await LoadFromDiskAsync(cancellationToken).ConfigureAwait(false);
                current = _store.CurrentIgnoringExpiry;
            }

            if (current is null)
                return TimeSpan.FromMinutes(5);

            if (current.IsExpired(DateTimeOffset.UtcNow))
            {
                _store.Set(null);
                _logger.LogWarning("Cached root.zone expired; falling back to live root queries");
                return current.Soa.RetryInterval;
            }

            return current.Soa.RetryInterval;
        }
    }

    private async Task LoadFromDiskAsync(CancellationToken cancellationToken)
    {
        var path = RootZonePaths.GetRootZonePath(_options);
        if (!File.Exists(path))
            return;

        try
        {
            var text = await File.ReadAllTextAsync(path, cancellationToken).ConfigureAwait(false);
            var loadedAt = new DateTimeOffset(File.GetLastWriteTimeUtc(path));
            var snapshot = ZoneFileParser.ParseRootZone(text, loadedAt);
            if (snapshot.IsExpired(DateTimeOffset.UtcNow))
            {
                _logger.LogWarning(
                    "On-disk root.zone at {Path} is expired (mtime {LoadedAt:u}); keeping until refresh succeeds",
                    path,
                    loadedAt);
            }

            // Keep serving until expire check in IRootZoneStore.Current / refresh loop clears it.
            _store.Set(snapshot);
            _logger.LogInformation(
                "Loaded root.zone from disk ({Count} owners, mtime {LoadedAt:u})",
                snapshot.RecordsByOwner.Count,
                loadedAt);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to load on-disk root.zone from {Path}", path);
        }
    }
}
