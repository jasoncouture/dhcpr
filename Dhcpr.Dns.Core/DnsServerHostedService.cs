using System.Net;
using System.Runtime.CompilerServices;

using Dhcpr.Core;
using Dhcpr.Dns.Core.Resolvers;

using DNS.Protocol;
using DNS.Server;

using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core;

public class DnsServerHostedService : IHostedService
{
    private readonly ILogger<DnsServer> _logger;
    private readonly DnsServer[] _servers;
    private readonly Task[] _runningServers;

    private static readonly ConditionalWeakTable<object, Tuple<ILogger<DnsServer>, IPEndPoint>> ServerData = new();

    public DnsServerHostedService(IDnsResolver resolver, IOptions<DnsConfiguration> dnsConfiguration,
        ILogger<DnsServer> logger)
    {
        _logger = logger;
        _servers = new DnsServer[dnsConfiguration.Value.ListenAddresses.Length];
        // Make sure no elements of the array are null, since the contract says so.
        _runningServers = Enumerable.Range(0, dnsConfiguration.Value.ListenAddresses.Length)
            .Select(i => Task.CompletedTask)
            .ToArray();
        for (var x = 0; x < dnsConfiguration.Value.ListenAddresses.Length; x++)
        {
            var endPoint = dnsConfiguration.Value.ListenAddresses[x].GetEndpoint(53);
            var server = CreateServer(endPoint, resolver);
            _servers[x] = server;
        }
    }

    private DnsServer CreateServer(IPEndPoint endPoint, IDnsResolver resolver)
    {
        var server = new DnsServer(resolver);
        server.Listening += OnListening;
        server.Requested += OnRequested;
        server.Responded += OnResponded;
        server.Errored += OnErrored;
        ServerData.Add(server, Tuple.Create(_logger, endPoint));
        _logger.LogInformation("Configured for {endPoint}",
            endPoint);
        return server;
    }

    private static (ILogger<DnsServer> logger, IPEndPoint endPoint) GetEventData(object? sender)
    {
        if (sender is null)
            throw new InvalidOperationException("Sender must be set.");
        if (!ServerData.TryGetValue(sender, out var data))
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
        var (logger, endPoint) = GetEventData(sender);
        logger.LogDebug("{endPoint} responded to {sender} with response code {responseCode}: {response}", endPoint,
            e.Remote, e.Response.ResponseCode, e.Response);
    }

    private static void OnRequested(object? sender, DnsServer.RequestedEventArgs e)
    {
        var (logger, endPoint) = GetEventData(sender);
        logger.LogDebug("{endPoint} received request from {sender}", endPoint, e.Remote);
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
            var (_, endpoint) = GetEventData(_servers[x]);
            _runningServers[x] = _servers[x].Listen(endpoint);
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