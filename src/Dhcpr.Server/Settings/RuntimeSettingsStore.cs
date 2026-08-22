using System.Text.Json;
using System.Text.Json.Serialization;

using Dhcpr.Core;
using Dhcpr.Dns.Core;
using Dhcpr.Dns.Core.RootZone;

using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace Dhcpr.Server.Settings;

public sealed class RuntimeSettingsStore : IRuntimeSettingsStore
{
    internal static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new ByteArrayNumberJsonConverter() }
    };

    private readonly ILogger<RuntimeSettingsStore> _logger;
    private readonly string _path;
    private readonly object _gate = new();
    private RuntimeEditableSettings _current;
    private DateTime _lastWriteTimeUtc = DateTime.MinValue;
    private CancellationTokenSource _changeSource = new();

    public RuntimeSettingsStore(
        IConfiguration configuration,
        IOptions<ApplicationConfiguration> application,
        ILogger<RuntimeSettingsStore> logger)
    {
        _logger = logger;
        _path = application.Value.GetSettingsPath();
        _current = ReadFromConfiguration(configuration);
        if (!TryLoadExisting())
            TrySeed();
    }

    public RuntimeEditableSettings Current
    {
        get
        {
            lock (_gate)
                return _current.Clone();
        }
    }

    public IChangeToken GetChangeToken()
    {
        lock (_gate)
            return new CancellationChangeToken(_changeSource.Token);
    }

    public void ReloadIfChanged()
    {
        DateTime writeTime;
        try
        {
            if (!File.Exists(_path))
                return;
            writeTime = File.GetLastWriteTimeUtc(_path);
        }
        catch (IOException)
        {
            return;
        }

        lock (_gate)
        {
            if (writeTime <= _lastWriteTimeUtc)
                return;
        }

        if (!TryReadFile(out var loaded, out var error) || loaded is null)
        {
            _logger.LogWarning("Ignoring invalid runtime settings file {Path}: {Error}", _path, error);
            return;
        }

        ReplaceCurrent(loaded, writeTime);
    }

    public async Task<string?> SaveAsync(RuntimeEditableSettings settings, CancellationToken cancellationToken)
    {
        var snapshot = settings.Clone();
        if (!TryValidate(snapshot, out var error))
            return error;

        var json = JsonSerializer.Serialize(ToFile(snapshot), JsonOptions);
        await AtomicFileReplace.WriteAsync(_path, json, cancellationToken).ConfigureAwait(false);
        var writeTime = File.GetLastWriteTimeUtc(_path);
        ReplaceCurrent(snapshot, writeTime);
        return null;
    }

    internal static bool TryValidate(RuntimeEditableSettings settings, out string? error)
    {
        var probe = new DnsConfiguration
        {
            ListenAddresses = ["udp://127.0.0.1:53"],
            RootServers = new RootServerConfiguration
            {
                Download = false,
                LoadFromSystem = false,
                Addresses = []
            },
            Routes = settings.Routes,
            BlackholeDomains = settings.BlackholeDomains,
            Dnssec = settings.Dnssec,
            HealthCheck = settings.HealthCheck,
            TrustAnchors = []
        };

        if (!probe.TryValidate(out error))
            return false;

        settings.BlackholeDomains = probe.BlackholeDomains;
        return settings.DynamicDns.Validate(out error);
    }

    internal static RuntimeEditableSettings FromFile(RuntimeSettingsFile file)
    {
        var dns = file.DNS ?? new DnsRuntimeSettingsSection();
        return new RuntimeEditableSettings
        {
            Routes = new Dictionary<string, DnsRouteConfiguration>(
                dns.Routes ?? new Dictionary<string, DnsRouteConfiguration>(),
                StringComparer.OrdinalIgnoreCase),
            BlackholeDomains = dns.BlackholeDomains ?? [],
            Dnssec = dns.Dnssec ?? new DnssecConfiguration(),
            HealthCheck = dns.HealthCheck ?? new DnsHealthCheckConfiguration(),
            DynamicDns = file.DynamicDns ?? new DynamicDnsConfiguration()
        };
    }

    internal static RuntimeEditableSettings ReadFromConfiguration(IConfiguration configuration)
    {
        var settings = new RuntimeEditableSettings();
        var routes = configuration.GetSection("DNS:Routes").Get<Dictionary<string, DnsRouteConfiguration>>();
        if (routes is not null)
            settings.Routes = new Dictionary<string, DnsRouteConfiguration>(routes, StringComparer.OrdinalIgnoreCase);

        settings.BlackholeDomains = configuration.GetSection("DNS:BlackholeDomains").Get<string[]>() ?? [];
        configuration.GetSection("DNS:Dnssec").Bind(settings.Dnssec);
        configuration.GetSection("DNS:HealthCheck").Bind(settings.HealthCheck);
        configuration.GetSection("DynamicDns").Bind(settings.DynamicDns);
        return settings;
    }

    private bool TryLoadExisting()
    {
        if (!File.Exists(_path))
            return false;

        if (!TryReadFile(out var loaded, out var error) || loaded is null)
        {
            _logger.LogError("Runtime settings file {Path} is invalid ({Error}); using appsettings seed in memory",
                _path, error);
            return true;
        }

        ReplaceCurrent(loaded, File.GetLastWriteTimeUtc(_path));
        return true;
    }

    private void TrySeed()
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(_path))!);
            using var stream = new FileStream(_path, FileMode.CreateNew, FileAccess.Write, FileShare.None);
            JsonSerializer.Serialize(stream, ToFile(_current), JsonOptions);
            _lastWriteTimeUtc = File.GetLastWriteTimeUtc(_path);
        }
        catch (IOException) when (File.Exists(_path))
        {
            TryLoadExisting();
        }
    }

    private bool TryReadFile(out RuntimeEditableSettings? settings, out string? error)
    {
        settings = null;
        error = null;
        try
        {
            var json = File.ReadAllText(_path);
            var file = JsonSerializer.Deserialize<RuntimeSettingsFile>(json, JsonOptions);
            if (file is null)
            {
                error = "settings.json deserialized to null";
                return false;
            }

            var loaded = FromFile(file);
            if (!TryValidate(loaded, out error))
                return false;

            settings = loaded;
            return true;
        }
        catch (Exception ex) when (ex is JsonException or IOException)
        {
            error = ex.Message;
            return false;
        }
    }

    private void ReplaceCurrent(RuntimeEditableSettings settings, DateTime writeTimeUtc)
    {
        CancellationTokenSource previous;
        lock (_gate)
        {
            _current = settings.Clone();
            _lastWriteTimeUtc = writeTimeUtc;
            previous = _changeSource;
            _changeSource = new CancellationTokenSource();
        }

        previous.Cancel();
        previous.Dispose();
    }

    private static RuntimeSettingsFile ToFile(RuntimeEditableSettings settings)
        => new()
        {
            DNS = new DnsRuntimeSettingsSection
            {
                Routes = settings.Routes,
                BlackholeDomains = settings.BlackholeDomains,
                Dnssec = settings.Dnssec,
                HealthCheck = settings.HealthCheck
            },
            DynamicDns = settings.DynamicDns
        };
}
