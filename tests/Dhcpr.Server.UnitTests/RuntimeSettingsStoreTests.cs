using Dhcpr.Core;
using Dhcpr.Dns.Core;
using Dhcpr.Server.Settings;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Dhcpr.Server.UnitTests;

public sealed class RuntimeSettingsStoreTests : IDisposable
{
    private readonly string _dataPath = Path.Combine(Path.GetTempPath(), "dhcpr-settings-" + Guid.NewGuid().ToString("N"));

    public void Dispose()
    {
        if (Directory.Exists(_dataPath))
            Directory.Delete(_dataPath, recursive: true);
    }

    [Fact]
    public void SeedWritesSettingsFileFromConfiguration()
    {
        var store = CreateStore();

        var path = Path.Combine(_dataPath, ApplicationConfiguration.SettingsFileName);
        Assert.True(File.Exists(path));
        Assert.True(store.Current.Routes.ContainsKey("example.com"));
        Assert.Equal("ads.example", Assert.Single(store.Current.BlackholeDomains));
        var seeded = Assert.Single(store.Current.Records);
        Assert.Equal("www.home.arpa", seeded.Name);
        Assert.Equal("A", seeded.Type);
        Assert.Equal("10.0.0.5", seeded.Value);
    }

    [Fact]
    public async Task SaveRemovesRoutesAndBlackholesAbsentFromThePatch()
    {
        var store = CreateStore();
        var next = store.Current;
        next.Routes.Clear();
        next.Routes["kept.test"] = new DnsRouteConfiguration { Upstreams = ["9.9.9.9:53"] };
        next.BlackholeDomains = ["evil.test"];

        var error = await store.SaveAsync(next, CancellationToken.None);

        Assert.Null(error);
        Assert.False(store.Current.Routes.ContainsKey("example.com"));
        Assert.Equal("9.9.9.9:53", Assert.Single(store.Current.Routes["kept.test"].Upstreams));
        Assert.Equal("evil.test", Assert.Single(store.Current.BlackholeDomains));
    }

    [Fact]
    public async Task SaveRejectsInvalidRoutesWithoutWriting()
    {
        var store = CreateStore();
        var before = File.ReadAllText(SettingsPath);
        var next = store.Current;
        next.Routes["broken"] = new DnsRouteConfiguration { Upstreams = [] };

        var error = await store.SaveAsync(next, CancellationToken.None);

        Assert.NotNull(error);
        Assert.Contains("broken", error, StringComparison.Ordinal);
        Assert.Equal(before, File.ReadAllText(SettingsPath));
        Assert.False(store.Current.Routes.ContainsKey("broken"));
    }

    [Fact]
    public async Task SaveRejectsInvalidRecordsWithoutWriting()
    {
        var store = CreateStore();
        var before = File.ReadAllText(SettingsPath);
        var next = store.Current;
        next.Records =
        [
            new DnsRecordConfiguration { Name = "www.home.arpa", Type = "CNAME", Value = "other.home.arpa" },
            new DnsRecordConfiguration { Name = "www.home.arpa", Type = "A", Value = "10.0.0.5" }
        ];

        var error = await store.SaveAsync(next, CancellationToken.None);

        Assert.NotNull(error);
        Assert.Contains("CNAME", error, StringComparison.Ordinal);
        Assert.Equal(before, File.ReadAllText(SettingsPath));
        Assert.Equal("www.home.arpa", Assert.Single(store.Current.Records).Name);
        Assert.Equal("A", store.Current.Records[0].Type);
    }

    [Fact]
    public async Task SaveReplacesRecords()
    {
        var store = CreateStore();
        var next = store.Current;
        next.Records =
        [
            new DnsRecordConfiguration
            {
                Name = "*.apps.home.arpa",
                Type = "AAAA",
                Value = "2001:db8::10",
                Clients = ["10.0.0.0/8"]
            }
        ];

        var error = await store.SaveAsync(next, CancellationToken.None);

        Assert.Null(error);
        var saved = Assert.Single(store.Current.Records);
        Assert.Equal("*.apps.home.arpa", saved.Name);
        Assert.Equal("AAAA", saved.Type);
        Assert.Equal("2001:db8::10", saved.Value);
        Assert.Equal("10.0.0.0/8", Assert.Single(saved.Clients));
    }

    [Fact]
    public async Task SaveSignalsChangeToken()
    {
        var store = CreateStore();
        var token = store.GetChangeToken();
        Assert.False(token.HasChanged);

        var next = store.Current;
        next.BlackholeDomains = ["sink.test"];
        var error = await store.SaveAsync(next, CancellationToken.None);

        Assert.Null(error);
        Assert.True(token.HasChanged);
        Assert.False(store.GetChangeToken().HasChanged);
    }

    [Fact]
    public void ReloadIfChangedPicksUpExternalWrite()
    {
        var store = CreateStore();
        var token = store.GetChangeToken();
        File.WriteAllText(SettingsPath,
            """
            {
              "DNS": {
                "Routes": {
                  "example.com": { "Upstreams": [ "10.0.0.1:53" ], "Clients": [] }
                },
                "Records": [
                  { "Name": "ns.external.test", "Type": "NS", "Value": "ns1.external.test" }
                ],
                "BlackholeDomains": [ "external.test" ],
                "Dnssec": { "Enabled": true, "AllowedAlgorithms": [], "DeniedAlgorithms": [] },
                "HealthCheck": { "Enabled": true, "Domains": [], "TimeoutSeconds": 5 }
              },
              "DynamicDns": { "Enabled": false, "Username": "", "Password": "", "TtlSeconds": 60, "TrustForwardedFor": false }
            }
            """);
        File.SetLastWriteTimeUtc(SettingsPath, DateTime.UtcNow.AddSeconds(2));

        store.ReloadIfChanged();

        Assert.True(token.HasChanged);
        Assert.Equal("external.test", Assert.Single(store.Current.BlackholeDomains));
        var record = Assert.Single(store.Current.Records);
        Assert.Equal("ns.external.test", record.Name);
        Assert.Equal("NS", record.Type);
    }

    private string SettingsPath => Path.Combine(_dataPath, ApplicationConfiguration.SettingsFileName);

    private RuntimeSettingsStore CreateStore()
    {
        Directory.CreateDirectory(_dataPath);
        var configuration = new ConfigurationManager();
        configuration["DNS:Routes:example.com:Upstreams:0"] = "10.0.0.1:53";
        configuration["DNS:Records:0:Name"] = "www.home.arpa";
        configuration["DNS:Records:0:Type"] = "A";
        configuration["DNS:Records:0:Value"] = "10.0.0.5";
        configuration["DNS:BlackholeDomains:0"] = "ads.example";
        configuration["DNS:Dnssec:Enabled"] = "true";
        configuration["DNS:HealthCheck:Enabled"] = "true";
        configuration["DNS:HealthCheck:TimeoutSeconds"] = "5";
        configuration["DynamicDns:Enabled"] = "false";
        var application = Options.Create(new ApplicationConfiguration { DataPath = _dataPath });
        return new RuntimeSettingsStore(configuration, application, NullLogger<RuntimeSettingsStore>.Instance);
    }
}
