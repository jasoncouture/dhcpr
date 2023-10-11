using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Protocol;

using DnsZone;

using Microsoft.Extensions.FileSystemGlobbing;
using Microsoft.Extensions.FileSystemGlobbing.Abstractions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Files;

public sealed class BindFileZoneProvider : IBindFileZoneProvider, IDisposable
{
    private readonly IDisposable? _subscription;
    private BindFileConfiguration _currentConfiguration;
    private LabelLookupCollection<DnsZoneFile> _zoneFileLookup = LabelLookupCollectionPool<DnsZoneFile>.Get();

    public BindFileZoneProvider(IOptionsMonitor<BindFileConfiguration> optionsMonitor, ILogger<BindFileZoneProvider> logger)
    {
        _subscription = optionsMonitor.OnChange(OnConfigurationChanged);
        _currentConfiguration = optionsMonitor.CurrentValue;
    }

    private async void OnConfigurationChanged(BindFileConfiguration configuration)
    {
        var lookup = LabelLookupCollectionPool<DnsZoneFile>.Get();
        await LoadZoneFilesAsync(lookup, configuration);
    }

    public DnsZoneFile? GetZoneOrNull(DomainLabels labels)
    {
        if (!_zoneFileLookup.TryGetNearestValue(labels, out var zoneFile)) return null;
        return zoneFile;
    }

    private async Task LoadZoneFilesAsync(LabelLookupCollection<DnsZoneFile> zoneFileLookup, BindFileConfiguration configuration)
    {
        var results = await Task.WhenAll(configuration.Paths.Select(i =>
            GetZonesFromPathAsync(i, configuration.BasePath ?? Environment.CurrentDirectory)));
        throw new NotImplementedException(); // TODO
    }

    private async Task<PooledList<DnsZoneFile>> GetZonesFromPathAsync(string path, string basePath)
    {
        var list = ListPool<DnsZoneFile>.Default.Get();
        if(Uri.IsWellFormedUriString(path, UriKind.Absolute) && Uri.TryCreate(path, UriKind.Absolute, out var uri))
        {
            var loadedFile = await LoadFromUriAsync(uri);
            if (loadedFile is not null) list.Add(loadedFile);
            return list;
        }
        var matcher = new Matcher();
        matcher.AddInclude(path);
        var result = matcher.Execute(new DirectoryInfoWrapper(Directory.CreateDirectory(Environment.CurrentDirectory)));
        foreach(var fileMatch in result.Files)
        {
            var fullPath = Path.GetFullPath(fileMatch.Path, Environment.CurrentDirectory);
            try
            {
    
            }
            catch (Exception ex)
            {
                
            }
        }

        throw new NotImplementedException(); // TODO
    }

    private static async Task<DnsZoneFile?> LoadFromUriAsync(Uri result)
    {
        throw new NotImplementedException();
    }

    public void Dispose()
    {
        _subscription?.Dispose();
        _zoneFileLookup.Dispose();
    }
}