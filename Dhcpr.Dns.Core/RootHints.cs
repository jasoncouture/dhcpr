﻿using System.Diagnostics;
using System.Globalization;
using System.Net;
using System.Net.Http.Headers;
using System.Text;

using Dhcpr.Core.Linq;

namespace Dhcpr.Dns.Core;

public static class RootHints
{
    private static readonly HashSet<IPAddress> _rootServerAddresses = new();
    public static string RootServerCacheFile { get; set; } = "root-servers.txt";
    private static DateTimeOffset _lastRefresh = DateTimeOffset.Now.AddDays(-2);

    public static TimeSpan TimeSinceLastRefresh => DateTimeOffset.Now - _lastRefresh;

    public static async ValueTask<IEnumerable<IPAddress>> GetRootServers(CancellationToken cancellationToken)
    {
        if (TimeSinceLastRefresh.TotalHours < 4)
            await RefreshAsync(cancellationToken).ConfigureAwait(false);

        lock (_rootServerAddresses)
            if (_rootServerAddresses.Count > 0)
                return _rootServerAddresses.ToPooledList();

        await RefreshAsync(cancellationToken).ConfigureAwait(false);

        // Don't save the cache file.
        lock (_rootServerAddresses)
            if (_rootServerAddresses.Count == 0)
                return _rootServerAddresses.ToPooledList();

        lock (_rootServerAddresses)
            return _rootServerAddresses.ToPooledList();
    }

    private static async Task SaveRootServersAsync(
        IEnumerable<IPAddress> rootServers,
        CancellationToken cancellationToken)
    {
        var output = new StringBuilder();
        output
            .AppendLine(
                $"; root server address cache file, created {DateTime.Now.ToString(CultureInfo.InvariantCulture)}")
            .AppendLine("; This file is automatically generated, and will be overwritten if modified.");
        foreach (var address in rootServers)
        {
            output.AppendLine(address.ToString());
        }

        var tempFile = Path.GetTempFileName();
        for (var i = 0; i < 5; i++)
        {
            try
            {
                await File.WriteAllTextAsync(tempFile, output.ToString(), cancellationToken).ConfigureAwait(false);
                File.Move(tempFile, RootServerCacheFile, true);
            }
            catch
            {
                await Task.Delay(5000, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private static readonly SemaphoreSlim _refreshSemaphore = new SemaphoreSlim(1, 1);

    public static async Task RefreshAsync(CancellationToken cancellationToken)
    {
        await _refreshSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            var addresses = ListPool<IPAddress>.Default.Get();
            if (File.Exists(RootServerCacheFile))
            {
                if ((DateTime.Now - File.GetCreationTime(RootServerCacheFile)).TotalDays < 1)
                {
                    ;
                    addresses.AddRange(await LoadRootServersFromFile(cancellationToken).ConfigureAwait(false));
                    Debug.WriteLine($"Loaded {addresses.Count} entries from dns cache file");
                }
            }

            // We either didn't use our cache file, it was empty, or something went wrong

            // Try getting it from internic, if this is successful, we can avoid making a bunch of DNS requests.
            if (addresses.Count == 0)
                addresses.AddRange(await LoadRootServersFromInternicAsync(cancellationToken).ConfigureAwait(false));

            // Try to use DNS to discover the root servers.
            if (addresses.Count == 0)
                addresses.AddRange(await LoadRootServersFromDns(cancellationToken).ConfigureAwait(false));


            // Try the local file if DNS lookup failed, we may have skipped trying to load it if it was too old
            if (addresses.Count == 0)
                addresses.AddRange(await LoadRootServersFromFile(cancellationToken).ConfigureAwait(false));
            lock (_rootServerAddresses)
            {
                _rootServerAddresses.Clear();
                foreach (var address in addresses)
                {
                    lock (_rootServerAddresses)
                        _rootServerAddresses.Add(address);
                }
            }

            await SaveRootServersAsync(addresses, cancellationToken).ConfigureAwait(false);
        }
        finally
        {
            _refreshSemaphore.Release();
        }
    }

    private static async Task<PooledList<IPAddress>> LoadRootServersFromFile(CancellationToken cancellationToken)
    {
        try
        {
            if (!File.Exists(RootServerCacheFile))
                return ListPool<IPAddress>.Default.Get();

            var addressStrings =
                await File.ReadAllLinesAsync(RootServerCacheFile, cancellationToken).ConfigureAwait(false);
            var addresses = addressStrings.Where(i => !i.Trim().StartsWith(';'))
                .Select(i => IPAddress.TryParse(i, out var address) ? address : null)
                .Where(i => i is not null)
                .Cast<IPAddress>()
                .ToPooledList();

            return addresses;
        }
        catch
        {
            return ListPool<IPAddress>.Default.Get();
        }
    }

    private static readonly HttpClient _httpClient = new()
    {
        DefaultRequestHeaders =
        {
            UserAgent = { new ProductInfoHeaderValue("(DHCPr DNS Server)") }
        }
    };

    private static async Task<PooledList<IPAddress>> LoadRootServersFromInternicAsync(
        CancellationToken cancellationToken)
    {
        var result = ListPool<IPAddress>.Default.Get();
        foreach (var url in new[]
                 {
                     "https://www.internic.net/domain/named.root",
                     "https://192.0.46.9/domain/named.root",
                     "http://192.0.46.9/domain/named.root"
                 })
        {
            Debug.WriteLine($"Trying to load root servers from internic, URL: {url}");
            try
            {
                var bindConfig = await _httpClient.GetStringAsync(url, cancellationToken).ConfigureAwait(false);
                var lines = bindConfig.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
                foreach (var line in lines.Select(i => i.Trim()))
                {
                    var maybeAddress = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries)
                        .LastOrDefault();
                    if (string.IsNullOrWhiteSpace(maybeAddress))
                        continue;
                    if (!IPAddress.TryParse(maybeAddress, out var ipAddress))
                        continue;

                    result.Add(ipAddress);
                }

                if (result.Count > 0)
                    return result;
            }
            catch
            {
                /* Ignored */
            }
        }

        return result;
    }

    private static async Task<PooledList<IPAddress>> LoadRootServersFromDns(CancellationToken cancellationToken)
    {
        var results = await Task
            .WhenAll("abcdefghijklm".Select(async i =>
                await GetRootServerAddresses(i, cancellationToken).ConfigureAwait(false))).ConfigureAwait(false);

        return results.SelectMany(i => i).ToPooledList();
    }

    private static async Task<IPAddress[]> GetRootServerAddresses(char rootServerId,
        CancellationToken cancellationToken)
    {
        try
        {
            Debug.WriteLine($"Getting root server {rootServerId}.root-servers.net addresses from DNS");
            return await System.Net.Dns.GetHostAddressesAsync($"{rootServerId}.root-servers.net", cancellationToken)
                .ConfigureAwait(false);
        }
        catch
        {
            return Array.Empty<IPAddress>();
        }
    }
}