using Dhcpr.Dns.Core;
using Dhcpr.Server.Settings;

namespace Dhcpr.Server.Components.Pages;

public partial class Settings
{
    private readonly List<RouteEdit> _routes = [];
    private string _blackhole = "";
    private bool _dnssecEnabled = true;
    private string _allowedAlgorithms = "";
    private string _deniedAlgorithms = "";
    private bool _healthEnabled = true;
    private string _healthDomains = "";
    private int _healthTimeout = 5;
    private bool _dynEnabled = true;
    private string _dynUsername = "";
    private string _dynPassword = "";
    private string _existingDynPassword = "";
    private int _dynTtl = 60;
    private bool _dynTrustForwardedFor;
    private string? _error;
    private bool _saved;
    private bool _saving;

    protected override void OnInitialized()
        => Load(Store.Current);

    private void AddRoute()
        => _routes.Add(new RouteEdit());

    private async Task SaveAsync()
    {
        _saving = true;
        _saved = false;
        _error = null;
        try
        {
            if (!TryBuild(out var settings, out var error))
            {
                _error = error;
                return;
            }

            _error = await Store.SaveAsync(settings, CancellationToken.None);
            if (_error is not null)
                return;

            _saved = true;
            _dynPassword = "";
            Load(Store.Current);
        }
        finally
        {
            _saving = false;
        }
    }

    private void Load(RuntimeEditableSettings settings)
    {
        _routes.Clear();
        foreach (var (suffix, route) in settings.Routes.OrderBy(static kv => kv.Key, StringComparer.OrdinalIgnoreCase))
        {
            _routes.Add(new RouteEdit
            {
                Suffix = suffix,
                Upstreams = JoinLines(route.Upstreams),
                Clients = JoinLines(route.Clients)
            });
        }

        _blackhole = JoinLines(settings.BlackholeDomains);
        _dnssecEnabled = settings.Dnssec.Enabled;
        _allowedAlgorithms = JoinBytes(settings.Dnssec.AllowedAlgorithms);
        _deniedAlgorithms = JoinBytes(settings.Dnssec.DeniedAlgorithms);
        _healthEnabled = settings.HealthCheck.Enabled;
        _healthDomains = JoinLines(settings.HealthCheck.Domains);
        _healthTimeout = settings.HealthCheck.TimeoutSeconds;
        _dynEnabled = settings.DynamicDns.Enabled;
        _dynUsername = settings.DynamicDns.Username;
        _existingDynPassword = settings.DynamicDns.Password;
        _dynTtl = settings.DynamicDns.TtlSeconds;
        _dynTrustForwardedFor = settings.DynamicDns.TrustForwardedFor;
    }

    private bool TryBuild(out RuntimeEditableSettings settings, out string? error)
    {
        settings = new RuntimeEditableSettings();
        error = null;

        if (!TryParseBytes(_allowedAlgorithms, "DNS:Dnssec:AllowedAlgorithms", out var allowed, out error) ||
            !TryParseBytes(_deniedAlgorithms, "DNS:Dnssec:DeniedAlgorithms", out var denied, out error))
        {
            return false;
        }

        var routes = new Dictionary<string, DnsRouteConfiguration>(StringComparer.OrdinalIgnoreCase);
        foreach (var route in _routes)
        {
            var suffix = route.Suffix.Trim().TrimEnd('.');
            if (string.IsNullOrWhiteSpace(suffix))
            {
                error = "Each route needs a domain suffix";
                return false;
            }

            if (!routes.TryAdd(suffix, new DnsRouteConfiguration
                {
                    Upstreams = SplitLines(route.Upstreams),
                    Clients = SplitLines(route.Clients)
                }))
            {
                error = $"Duplicate route suffix: {suffix}";
                return false;
            }
        }

        settings.Routes = routes;
        settings.BlackholeDomains = SplitLines(_blackhole);
        settings.Dnssec = new DnssecConfiguration
        {
            Enabled = _dnssecEnabled,
            AllowedAlgorithms = allowed,
            DeniedAlgorithms = denied
        };
        settings.HealthCheck = new DnsHealthCheckConfiguration
        {
            Enabled = _healthEnabled,
            Domains = SplitLines(_healthDomains),
            TimeoutSeconds = _healthTimeout
        };
        settings.DynamicDns = new DynamicDnsConfiguration
        {
            Enabled = _dynEnabled,
            Username = _dynUsername,
            Password = string.IsNullOrEmpty(_dynPassword) ? _existingDynPassword : _dynPassword,
            TtlSeconds = _dynTtl,
            TrustForwardedFor = _dynTrustForwardedFor
        };
        return true;
    }

    private static string[] SplitLines(string text)
        => text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static string JoinLines(string[]? values)
        => values is { Length: > 0 } ? string.Join('\n', values) : "";

    private static string JoinBytes(byte[]? values)
        => values is { Length: > 0 } ? string.Join(',', values) : "";

    private static bool TryParseBytes(string text, string name, out byte[] values, out string? error)
    {
        values = [];
        error = null;
        if (string.IsNullOrWhiteSpace(text))
            return true;

        var parts = text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        values = new byte[parts.Length];
        for (var i = 0; i < parts.Length; i++)
        {
            if (byte.TryParse(parts[i], out var value))
            {
                values[i] = value;
                continue;
            }

            error = $"{name} contains an invalid byte: {parts[i]}";
            return false;
        }

        return true;
    }

    private sealed class RouteEdit
    {
        public string Suffix { get; set; } = "";
        public string Upstreams { get; set; } = "";
        public string Clients { get; set; } = "";
    }
}
