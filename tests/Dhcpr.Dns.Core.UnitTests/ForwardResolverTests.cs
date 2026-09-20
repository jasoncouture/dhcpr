using System.Collections.Immutable;
using System.Net;

using Dhcpr.Dns.Core.Authoritative;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Forwarder;

using Microsoft.Extensions.Options;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class ForwardResolverTests
{
    private static readonly IPEndPoint _nebulaForwarder = new(IPAddress.Parse("10.245.1.1"), 5301);
    private static readonly IPAddress _answerAddress = IPAddress.Parse("10.0.0.50");

    [Fact]
    public async Task MatchingSuffixForwardsToRouteEndpoints()
    {
        ImmutableArray<IPEndPoint>? directed = null;
        var internalClient = new CapturingInternalDomainClient((message, upstream) =>
        {
            directed = upstream;
            return DomainMessage.CreateResponse(
                message,
                new[]
                {
                    new DomainResourceRecord(
                        message.Questions[0].Name,
                        DomainRecordType.A,
                        DomainRecordClass.IN,
                        TimeSpan.FromSeconds(60),
                        new IPAddressData(_answerAddress))
                },
                responseCode: DomainResponseCode.NoError);
        });

        var resolver = CreateResolver(internalClient.Client, new Dictionary<string, DnsRouteConfiguration>
        {
            ["nebula"] = Route(_nebulaForwarder.ToString())
        });

        var request = DomainMessage.CreateRequest("nas.nebula", DomainRecordType.A);
        var result = await resolver.ProcessAsync(
            new DomainMessageContext(null, null, request),
            CancellationToken.None);

        Assert.NotNull(result);
        Assert.NotNull(directed);
        Assert.Contains(_nebulaForwarder, directed!.Value);
        Assert.Contains(result!.Records.Answers, r =>
            r.Type == DomainRecordType.A &&
            ((IPAddressData)r.Data).Address.Equals(_answerAddress));
    }

    [Fact]
    public async Task LongestSuffixWins()
    {
        var specific = new IPEndPoint(IPAddress.Parse("10.1.1.1"), 53);
        var broad = new IPEndPoint(IPAddress.Parse("10.2.2.2"), 53);
        ImmutableArray<IPEndPoint>? directed = null;
        var internalClient = new CapturingInternalDomainClient((_, upstream) =>
        {
            directed = upstream;
            return DomainMessage.CreateResponse(
                DomainMessage.CreateRequest("a.b.example"),
                DomainResourceRecords.Empty,
                DomainResponseCode.NoError);
        });

        var resolver = CreateResolver(internalClient.Client, new Dictionary<string, DnsRouteConfiguration>
        {
            ["example"] = Route(broad.ToString()),
            ["b.example"] = Route(specific.ToString())
        });

        await resolver.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("a.b.example")),
            CancellationToken.None);

        Assert.NotNull(directed);
        Assert.Contains(specific, directed!.Value);
        Assert.DoesNotContain(broad, directed.Value);
    }

    [Fact]
    public async Task NonMatchingNameReturnsNull()
    {
        var internalClient = new CapturingInternalDomainClient((_, _) =>
            throw new InvalidOperationException("should not forward"));
        var resolver = CreateResolver(internalClient.Client, new Dictionary<string, DnsRouteConfiguration>
        {
            ["nebula"] = Route(_nebulaForwarder.ToString())
        });

        var result = await resolver.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("www.example.com")),
            CancellationToken.None);

        Assert.Equal(DomainResponseCode.ServerFailure, result.Flags.ResponseCode);
        Assert.Empty(internalClient.Calls);
    }

    [Fact]
    public async Task MissCallsInner()
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        var request = DomainMessage.CreateRequest("www.example.com");
        var passed = DomainMessage.CreateResponse(request, responseCode: DomainResponseCode.NoError);
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(passed);

        var resolver = CreateResolver(
            Substitute.For<IInternalDomainClient>(),
            new Dictionary<string, DnsRouteConfiguration>
            {
                ["nebula"] = Route(_nebulaForwarder.ToString())
            },
            inner);

        var result = await resolver.ProcessAsync(
            new DomainMessageContext(null, null, request),
            CancellationToken.None);

        Assert.Same(passed, result);
        await inner.Received(1)
            .ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>());
    }

    [Fact]
    public async Task EmptyRoutesReturnsNull()
    {
        var internalClient = new CapturingInternalDomainClient((_, _) =>
            throw new InvalidOperationException("should not forward"));
        var resolver = CreateResolver(internalClient.Client, new Dictionary<string, DnsRouteConfiguration>());

        var result = await resolver.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("nas.nebula")),
            CancellationToken.None);

        Assert.Equal(DomainResponseCode.ServerFailure, result.Flags.ResponseCode);
    }

    [Fact]
    public async Task DirectedUpstreamContextIsIgnored()
    {
        var internalClient = new CapturingInternalDomainClient((_, _) =>
            throw new InvalidOperationException("should not forward"));
        var resolver = CreateResolver(internalClient.Client, new Dictionary<string, DnsRouteConfiguration>
        {
            ["nebula"] = Route(_nebulaForwarder.ToString())
        });

        var result = await resolver.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("nas.nebula"))
            {
                UpstreamEndpoints = ImmutableArray.Create(_nebulaForwarder)
            },
            CancellationToken.None);

        Assert.Equal(DomainResponseCode.ServerFailure, result.Flags.ResponseCode);
    }

    [Fact]
    public async Task ClientInAllowedSubnetUsesRoute()
    {
        ImmutableArray<IPEndPoint>? directed = null;
        var internalClient = new CapturingInternalDomainClient((_, upstream) =>
        {
            directed = upstream;
            return DomainMessage.CreateResponse(
                DomainMessage.CreateRequest("nas.nebula"),
                DomainResourceRecords.Empty,
                DomainResponseCode.NoError);
        });

        var resolver = CreateResolver(internalClient.Client, new Dictionary<string, DnsRouteConfiguration>
        {
            ["nebula"] = Route(_nebulaForwarder.ToString(), "10.245.0.0/16")
        });

        var result = await resolver.ProcessAsync(
            new DomainMessageContext(
                new IPEndPoint(IPAddress.Parse("10.245.9.4"), 53000),
                null,
                DomainMessage.CreateRequest("nas.nebula")),
            CancellationToken.None);

        Assert.NotNull(result);
        Assert.Contains(_nebulaForwarder, directed!.Value);
    }

    [Fact]
    public async Task ClientOutsideAllowedSubnetSkipsRoute()
    {
        var internalClient = new CapturingInternalDomainClient((_, _) =>
            throw new InvalidOperationException("should not forward"));
        var resolver = CreateResolver(internalClient.Client, new Dictionary<string, DnsRouteConfiguration>
        {
            ["nebula"] = Route(_nebulaForwarder.ToString(), "10.245.0.0/16")
        });

        var result = await resolver.ProcessAsync(
            new DomainMessageContext(
                new IPEndPoint(IPAddress.Parse("192.0.2.10"), 53000),
                null,
                DomainMessage.CreateRequest("nas.nebula")),
            CancellationToken.None);

        Assert.Equal(DomainResponseCode.ServerFailure, result.Flags.ResponseCode);
        Assert.Empty(internalClient.Calls);
    }

    [Fact]
    public async Task RestrictedLongestSuffixFallsThroughToShorterRoute()
    {
        var specific = new IPEndPoint(IPAddress.Parse("10.1.1.1"), 53);
        var broad = new IPEndPoint(IPAddress.Parse("10.2.2.2"), 53);
        ImmutableArray<IPEndPoint>? directed = null;
        var internalClient = new CapturingInternalDomainClient((_, upstream) =>
        {
            directed = upstream;
            return DomainMessage.CreateResponse(
                DomainMessage.CreateRequest("a.b.example"),
                DomainResourceRecords.Empty,
                DomainResponseCode.NoError);
        });

        var resolver = CreateResolver(internalClient.Client, new Dictionary<string, DnsRouteConfiguration>
        {
            ["b.example"] = Route(specific.ToString(), "10.0.0.0/8"),
            ["example"] = Route(broad.ToString())
        });

        await resolver.ProcessAsync(
            new DomainMessageContext(
                new IPEndPoint(IPAddress.Parse("192.0.2.10"), 53000),
                null,
                DomainMessage.CreateRequest("a.b.example")),
            CancellationToken.None);

        Assert.NotNull(directed);
        Assert.Contains(broad, directed!.Value);
        Assert.DoesNotContain(specific, directed.Value);
    }

    [Fact]
    public async Task UnknownClientSkipsRestrictedRoute()
    {
        var internalClient = new CapturingInternalDomainClient((_, _) =>
            throw new InvalidOperationException("should not forward"));
        var resolver = CreateResolver(internalClient.Client, new Dictionary<string, DnsRouteConfiguration>
        {
            ["nebula"] = Route(_nebulaForwarder.ToString(), "10.245.0.0/16")
        });

        var result = await resolver.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("nas.nebula")),
            CancellationToken.None);

        Assert.Equal(DomainResponseCode.ServerFailure, result.Flags.ResponseCode);
    }

    [Fact]
    public void InvalidClientCidrFailsValidation()
    {
        var configuration = new DnsConfiguration
        {
            RootServers = new RootServerConfiguration { Addresses = ["198.41.0.4:53"] },
            Routes = new Dictionary<string, DnsRouteConfiguration>
            {
                ["nebula"] = Route(_nebulaForwarder.ToString(), "not-a-network")
            },
            ListenAddresses = ["udp://127.0.0.1:5353"]
        };

        Assert.False(configuration.TryValidate(out var error));
        Assert.Contains("Clients", error);
    }

    private static DnsRouteConfiguration Route(string upstream, params string[] clients) =>
        new() { Upstreams = [upstream], Clients = clients };

    private static ForwardResolver CreateResolver(
        IInternalDomainClient internalClient,
        Dictionary<string, DnsRouteConfiguration> routes,
        IDomainMessageMiddleware? inner = null)
    {
        var configuration = new DnsConfiguration
        {
            RootServers = new RootServerConfiguration
            {
                Addresses = new[] { "198.41.0.4:53" }
            },
            Routes = routes,
            ListenAddresses = new[] { "udp://127.0.0.1:5353" }
        };
        Assert.True(configuration.Validate());

        return new ForwardResolver(
            inner ?? PassThroughInner(),
            Monitor(configuration),
            internalClient,
            new AuthoritativeZoneStore());
    }

    private static IDomainMessageMiddleware PassThroughInner()
    {
        var inner = Substitute.For<IDomainMessageMiddleware>();
        inner.ProcessAsync(Arg.Any<DomainMessageContext>(), Arg.Any<CancellationToken>())
            .Returns(call => DomainMessage.CreateResponse(
                call.Arg<DomainMessageContext>().DomainMessage,
                DomainResourceRecords.Empty,
                DomainResponseCode.ServerFailure));
        return inner;
    }

    private static IOptionsMonitor<T> Monitor<T>(T value)
    {
        var monitor = Substitute.For<IOptionsMonitor<T>>();
        monitor.CurrentValue.Returns(value);
        monitor.Get(Arg.Any<string?>()).Returns(value);
        return monitor;
    }

    private sealed class CapturingInternalDomainClient
    {
        public IInternalDomainClient Client { get; }
        public List<string> Calls { get; } = [];

        public CapturingInternalDomainClient(
            Func<DomainMessage, ImmutableArray<IPEndPoint>, DomainMessage> handler)
        {
            var client = Substitute.For<IInternalDomainClient>();
            client.SendAsync(Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
                .Returns(_ => ValueTask.FromException<DomainMessage>(new NotSupportedException()));
            client.SendAsync(Arg.Any<DomainMessageContext>(), Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
                .Returns(_ => ValueTask.FromException<DomainMessage>(new NotSupportedException()));
            client.SendAsync(
                    Arg.Any<DomainMessageContext>(),
                    Arg.Any<DomainMessage>(),
                    Arg.Any<ImmutableArray<IPEndPoint>>(),
                    Arg.Any<CancellationToken>())
                .Returns(ci =>
                {
                    var message = ci.ArgAt<DomainMessage>(1);
                    Calls.Add($"{message.Questions[0].Name}/{message.Questions[0].Type}");
                    return new ValueTask<DomainMessage>(handler.Invoke(message, ci.ArgAt<ImmutableArray<IPEndPoint>>(2)));
                });
            Client = client;
        }
    }
}
