using System.Threading.Channels;

using Dhcpr.Core;
using Dhcpr.Dns.Core.Resolvers.Caching;

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Authoritative;

/// <summary>
/// Loads <c>{DataPath}/zones/**/*.bind</c>. The file watcher only signals a channel;
/// a single hosted loop owns debounce + reload (no fire-and-forget tasks).
/// </summary>
public sealed class AuthoritativeZoneLoader : BackgroundService
{
    private static readonly TimeSpan _debounce = TimeSpan.FromMilliseconds(500);

    private readonly IAuthoritativeZoneStore _store;
    private readonly IDnsResponseCache _cache;
    private readonly IOptionsMonitor<ApplicationConfiguration> _application;
    private readonly ILogger<AuthoritativeZoneLoader> _logger;

    public AuthoritativeZoneLoader(
        IAuthoritativeZoneStore store,
        IDnsResponseCache cache,
        IOptionsMonitor<ApplicationConfiguration> application,
        ILogger<AuthoritativeZoneLoader> logger)
    {
        _store = store;
        _cache = cache;
        _application = application;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var dir = EnsureZonesDirectory();
        Reload(dir);

        var reloadSignals = Channel.CreateUnbounded<bool>(
            new UnboundedChannelOptions
            {
                SingleReader = true,
                SingleWriter = false,
                AllowSynchronousContinuations = false
            });

        using var watcher = new FileSystemWatcher(dir)
        {
            Filter = "*.bind",
            IncludeSubdirectories = true,
            NotifyFilter = NotifyFilters.FileName
                           | NotifyFilters.DirectoryName
                           | NotifyFilters.LastWrite
                           | NotifyFilters.CreationTime
                           | NotifyFilters.Size
        };

        void OnFsEvent(object sender, FileSystemEventArgs args) => reloadSignals.Writer.TryWrite(true);
        void OnRenamed(object sender, RenamedEventArgs args) => reloadSignals.Writer.TryWrite(true);

        watcher.Created += OnFsEvent;
        watcher.Changed += OnFsEvent;
        watcher.Deleted += OnFsEvent;
        watcher.Renamed += OnRenamed;
        watcher.EnableRaisingEvents = true;

        while (await reloadSignals.Reader.WaitToReadAsync(stoppingToken).ConfigureAwait(false))
        {
            while (reloadSignals.Reader.TryRead(out _))
            {
            }

            try
            {
                await Task.Delay(_debounce, stoppingToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }

            // Coalesce anything that arrived during the debounce window.
            while (reloadSignals.Reader.TryRead(out _))
            {
            }

            try
            {
                Reload(EnsureZonesDirectory());
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to reload authoritative zones");
            }
        }
    }

    private string EnsureZonesDirectory()
    {
        var dir = _application.CurrentValue.GetZonesDirectory();
        Directory.CreateDirectory(dir);
        return dir;
    }

    private void Reload(string directory)
    {
        var files = Directory.EnumerateFiles(directory, "*.bind", SearchOption.AllDirectories)
            .OrderBy(f => f, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var zones = new List<AuthoritativeZone>();
        var seenApex = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var file in files)
        {
            try
            {
                var zone = AuthoritativeZoneBuilder.ParseFile(file);
                if (!seenApex.Add(zone.Apex))
                {
                    _logger.LogWarning(
                        "Duplicate zone apex {Apex} in {Path}; keeping first loaded zone",
                        zone.Apex,
                        file);
                    continue;
                }

                zones.Add(zone);
                _logger.LogInformation("Loaded authoritative zone {Apex} from {Path}", zone.Apex, file);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Skipping authoritative zone file {Path}", file);
            }
        }

        _store.Publish(zones);
        _cache.Clear();
        _logger.LogDebug("Published {Count} authoritative zone(s)", zones.Count);
    }
}
