using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Runtime.CompilerServices;
using Dhcpr.Core;
using DNS.Client.RequestResolver;
using DNS.Server;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core;

public class RootServerConfiguration : IValidateSelf
{
    public string CacheFilePath { get; set; } = "root-servers.txt";
    public bool Download { get; set; } = true;
    public bool LoadFromSystem { get; set; } = true;
    public string[] Addresses { get; set; } = Array.Empty<string>();

    public Uri[] DownloadUrls { get; set; } =
    {
        new Uri("https://www.internic.net/domain/named.root"),
        new Uri("https://192.0.46.9/domain/named.root"),
        new Uri("http://192.0.46.9/domain/named.root")
    };

    [SuppressMessage("ReSharper", "ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract",
        Justification = "Values are set by reflection")]
    public bool Validate()
    {
        if (CacheFilePath is null) return false;
        if (Addresses is null) return false;
        if (DownloadUrls is null) return false;
        if (DownloadUrls.Any(i => i is null || !i.IsAbsoluteUri)) return false;
        if (Addresses.Any(i => i is null)) return false;
        return Addresses.All(i => i.IsValidIPAddress());
    }
}


public static class DnsServiceProviderExtensions
{
    public static IServiceCollection AddDns(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddHostedService<DnsServerHostedService>();
        services.Configure<DnsConfiguration>(configuration).AddValidation<DnsConfiguration>();
        services.AddSingleton<IDnsResolver, DnsResolver>();
        services.AddSingleton<IParallelDnsResolver, IParallelDnsResolver>();
        services.AddSingleton<ISequentialDnsResolver, SequentialDnsResolver>();
        services.AddSingleton<IRequestResolver, InternalResolver>();
        services.Configure<DnsConfiguration>(configuration).AddValidation<DnsConfiguration>();
        return services;
    }
}

public class DnsServerHostedService : IHostedService
{
    private readonly ILogger<DnsServer> _logger;
    private readonly DnsServer[] _servers;
    private readonly Task[] _runningServers;

    private static readonly ConditionalWeakTable<object, Tuple<ILogger<DnsServer>, IPEndPoint>> _eventHandlers = new();

    public DnsServerHostedService(IDnsResolver resolver, DnsConfiguration dnsConfiguration,
        ILogger<DnsServer> logger)
    {
        _logger = logger;
        _servers = new DnsServer[dnsConfiguration.ListenAddresses.Length];
        // Make sure no elements of the array are null, since the contract says so.
        _runningServers = Enumerable.Range(0, dnsConfiguration.ListenAddresses.Length)
            .Select(i => Task.CompletedTask)
            .ToArray();
        for (var x = 0; x < dnsConfiguration.ListenAddresses.Length; x++)
        {
            var endPoint = dnsConfiguration.ListenAddresses[x].GetEndpoint(53);
            var server = CreateServer(endPoint, resolver);
            _servers[x] = server;
        }
    }

    private  DnsServer CreateServer(IPEndPoint endPoint, IDnsResolver resolver)
    {
        var server = new DnsServer(resolver, endPoint);
        server.Listening += OnListening;
        server.Requested += OnRequested;
        server.Responded += OnResponded; 
        server.Errored += OnErrored;
        _eventHandlers.Add(server, Tuple.Create(_logger, endPoint));
        _logger.LogInformation("Configured for {endPoint}",
            endPoint);
        return server;
    }

    private static (ILogger<DnsServer> logger, IPEndPoint endPoint) GetEventData(object? sender)
    {
        if (sender is null) 
            throw new InvalidOperationException("Sender must be set.");
        if (!_eventHandlers.TryGetValue(sender, out var data)) 
            throw new InvalidOperationException("What?");

        return (data.Item1, data.Item2);
    }
    private static void OnErrored(object? sender, DnsServer.ErroredEventArgs e)
    {
        var (logger, endPoint) = GetEventData(sender);
        logger.LogError(e.Exception, "DNS Server instance listening on {endPoint} has failed with an error", endPoint);   
    }

    private static void OnResponded(object? sender, DnsServer.RespondedEventArgs e)
    {
    }

    private static void OnRequested(object? sender, DnsServer.RequestedEventArgs e)
    {
    }

    private static void OnListening(object? sender, EventArgs e)
    {
        var (logger, endPoint) = GetEventData(sender);
        logger.LogInformation("Server has started listening on {endPoint}", endPoint);
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        for (var x = 0; x < _servers.Length; x++)
        {
            _runningServers[x] = _servers[x].Listen();
            _logger.LogInformation("Started server {serverId}", x);
        }

        return Task.CompletedTask;
    }
    

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        foreach (var server in _servers)
        {
            server.Listening -= OnListening;
            server.Requested -= OnRequested;
            server.Responded -= OnResponded;
            server.Errored -= OnErrored;
            server.Dispose();
        }

        await Task.WhenAll(
                _runningServers
                    .Where(i => i.IsCompletedSuccessfully == false)
                    .Select(async x => await x.IgnoreExceptionsAsync().ConfigureAwait(false))
            )
            .ConfigureAwait(false);
    }

}