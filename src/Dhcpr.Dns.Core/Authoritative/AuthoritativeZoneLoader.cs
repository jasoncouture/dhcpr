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
public sealed partial class AuthoritativeZoneLoader : BackgroundService
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
                LogReloadFailed(_logger, ex);
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
                    LogDuplicateZoneApex(_logger, zone.Apex, file);
                    continue;
                }

                zones.Add(zone);
                LogLoadedZone(_logger, zone.Apex, file);
            }
            catch (Exception ex)
            {
                LogSkippingZoneFile(_logger, ex, file);
            }
        }

        _store.Publish(zones);
        _cache.Clear();
        LogPublishedZones(_logger, zones.Count);
    }

    [LoggerMessage(Level = LogLevel.Error, Message = "Failed to reload authoritative zones")]
    private static partial void LogReloadFailed(ILogger logger, Exception exception);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Duplicate zone apex {Apex} in {Path}; keeping first loaded zone")]
    private static partial void LogDuplicateZoneApex(ILogger logger, string apex, string path);

    [LoggerMessage(Level = LogLevel.Information, Message = "Loaded authoritative zone {Apex} from {Path}")]
    private static partial void LogLoadedZone(ILogger logger, string apex, string path);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Skipping authoritative zone file {Path}")]
    private static partial void LogSkippingZoneFile(ILogger logger, Exception exception, string path);

    [LoggerMessage(Level = LogLevel.Debug, Message = "Published {Count} authoritative zone(s)")]
    private static partial void LogPublishedZones(ILogger logger, int count);
}
