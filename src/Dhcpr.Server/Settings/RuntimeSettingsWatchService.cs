using Dhcpr.Core;

using Microsoft.Extensions.Options;

namespace Dhcpr.Server.Settings;

public sealed class RuntimeSettingsWatchService : BackgroundService
{
    private static readonly TimeSpan PollInterval = TimeSpan.FromSeconds(5);

    private readonly IRuntimeSettingsStore _store;
    private readonly IOptions<ApplicationConfiguration> _application;
    private FileSystemWatcher? _watcher;

    public RuntimeSettingsWatchService(
        IRuntimeSettingsStore store,
        IOptions<ApplicationConfiguration> application)
    {
        _store = store;
        _application = application;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var path = _application.Value.GetSettingsPath();
        var directory = Path.GetDirectoryName(Path.GetFullPath(path));
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
            _watcher = new FileSystemWatcher(directory, ApplicationConfiguration.SettingsFileName)
            {
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size
            };
            _watcher.Changed += OnChanged;
            _watcher.Created += OnChanged;
            _watcher.Renamed += OnChanged;
            _watcher.EnableRaisingEvents = true;
        }

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                await Task.Delay(PollInterval, stoppingToken).ConfigureAwait(false);
                _store.ReloadIfChanged();
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
    }

    private void OnChanged(object sender, FileSystemEventArgs e)
        => _store.ReloadIfChanged();

    public override void Dispose()
    {
        if (_watcher is not null)
        {
            _watcher.EnableRaisingEvents = false;
            _watcher.Changed -= OnChanged;
            _watcher.Created -= OnChanged;
            _watcher.Renamed -= OnChanged;
            _watcher.Dispose();
        }

        base.Dispose();
    }
}
