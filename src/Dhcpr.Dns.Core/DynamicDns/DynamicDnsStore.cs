using System.Collections.Concurrent;
using System.Net;
using System.Text.Json;
using System.Text.Json.Serialization;

using Dhcpr.Core;
using Dhcpr.Dns.Core.Protocol.Zone;
using Dhcpr.Dns.Core.RootZone;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.DynamicDns;

public sealed partial class DynamicDnsStore : IDynamicDnsStore
{
    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly ConcurrentDictionary<string, DynamicDnsEntry> _entries =
        new(StringComparer.OrdinalIgnoreCase);

    private readonly IOptionsMonitor<ApplicationConfiguration> _application;
    private readonly IOptionsMonitor<DynamicDnsConfiguration> _options;
    private readonly ILogger<DynamicDnsStore> _logger;
    private readonly object _persistGate = new();

    public DynamicDnsStore(
        IOptionsMonitor<ApplicationConfiguration> application,
        IOptionsMonitor<DynamicDnsConfiguration> options,
        ILogger<DynamicDnsStore> logger)
    {
        _application = application;
        _options = options;
        _logger = logger;
    }

    public TimeSpan Ttl => TimeSpan.FromSeconds(Math.Clamp(_options.CurrentValue.TtlSeconds, 1, 86400));

    public void LoadFromDisk()
    {
        var path = _application.CurrentValue.GetDynamicDnsPath();
        if (!File.Exists(path))
            return;

        try
        {
            var json = File.ReadAllText(path);
            var loaded = JsonSerializer.Deserialize<Dictionary<string, DynamicDnsEntry>>(json, _jsonOptions);
            if (loaded is null)
                return;

            _entries.Clear();
            foreach (var (name, entry) in loaded)
            {
                var key = RootZoneSnapshot.NormalizeOwner(name);
                if (key.Length == 0)
                    continue;
                _entries[key] = entry;
            }

            LogLoadedEntries(_logger, _entries.Count, path);
        }
        catch (Exception ex)
        {
            LogLoadFailed(_logger, ex, path);
        }
    }

    public bool TryGet(string name, out DynamicDnsEntry entry)
        => _entries.TryGetValue(RootZoneSnapshot.NormalizeOwner(name), out entry!);

    public DynamicDnsUpsertResult Upsert(string name, IPAddress? ipv4, IPAddress? ipv6)
    {
        if (ipv4 is null && ipv6 is null)
            throw new ArgumentException("At least one address is required.");

        var key = RootZoneSnapshot.NormalizeOwner(name);
        var now = DateTimeOffset.UtcNow;

        while (true)
        {
            if (_entries.TryGetValue(key, out var existing))
            {
                var next = Clone(existing);
                var changed = false;

                if (ipv4 is not null)
                {
                    var text = ipv4.ToString();
                    if (!string.Equals(next.Ipv4, text, StringComparison.OrdinalIgnoreCase))
                    {
                        next.Ipv4 = text;
                        changed = true;
                    }
                }

                if (ipv6 is not null)
                {
                    var text = ipv6.ToString();
                    if (!string.Equals(next.Ipv6, text, StringComparison.OrdinalIgnoreCase))
                    {
                        next.Ipv6 = text;
                        changed = true;
                    }
                }

                if (!changed)
                    return DynamicDnsUpsertResult.Unchanged;

                next.UpdatedAt = now;
                if (_entries.TryUpdate(key, next, existing))
                {
                    Persist();
                    return DynamicDnsUpsertResult.Updated;
                }

                continue;
            }

            var created = new DynamicDnsEntry
            {
                Ipv4 = ipv4?.ToString(),
                Ipv6 = ipv6?.ToString(),
                UpdatedAt = now
            };
            if (_entries.TryAdd(key, created))
            {
                Persist();
                return DynamicDnsUpsertResult.Updated;
            }
        }
    }

    private void Persist()
    {
        lock (_persistGate)
        {
            var path = _application.CurrentValue.GetDynamicDnsPath();
            var snapshot = _entries.ToDictionary(
                static kv => kv.Key,
                static kv => kv.Value,
                StringComparer.OrdinalIgnoreCase);
            var json = JsonSerializer.Serialize(snapshot, _jsonOptions);
            AtomicFileReplace.WriteAsync(path, json, CancellationToken.None)
                .GetAwaiter()
                .GetResult();
        }
    }

    private static DynamicDnsEntry Clone(DynamicDnsEntry entry)
        => new()
        {
            Ipv4 = entry.Ipv4,
            Ipv6 = entry.Ipv6,
            UpdatedAt = entry.UpdatedAt
        };

    [LoggerMessage(Level = LogLevel.Information, Message = "Loaded {Count} dynamic DNS entr(y/ies) from {Path}")]
    private static partial void LogLoadedEntries(ILogger logger, int count, string path);

    [LoggerMessage(Level = LogLevel.Warning, Message = "Failed to load dynamic DNS file {Path}")]
    private static partial void LogLoadFailed(ILogger logger, Exception exception, string path);
}
