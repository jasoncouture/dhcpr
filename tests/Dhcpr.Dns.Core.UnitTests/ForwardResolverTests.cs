using System.Collections.Immutable;
using System.Net;

using Dhcpr.Dns.Core;
using Dhcpr.Dns.Core.Authoritative;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Forwarder;

using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.UnitTests;

public class ForwardResolverTests
{
    private static readonly IPEndPoint NebulaForwarder = new(IPAddress.Parse("10.245.1.1"), 5301);
    private static readonly IPAddress AnswerAddress = IPAddress.Parse("10.0.0.50");

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
                        new IPAddressData(AnswerAddress))
                },
                responseCode: DomainResponseCode.NoError);
        });

        var resolver = CreateResolver(internalClient, new Dictionary<string, string[]>
        {
            ["nebula"] = new[] { NebulaForwarder.ToString() }
        });

        var request = DomainMessage.CreateRequest("nas.nebula", DomainRecordType.A);
        var result = await resolver.ProcessAsync(
            new DomainMessageContext(null, null, request),
            CancellationToken.None);

        Assert.NotNull(result);
        Assert.NotNull(directed);
        Assert.Contains(NebulaForwarder, directed!.Value);
        Assert.Contains(result!.Records.Answers, r =>
            r.Type == DomainRecordType.A &&
            ((IPAddressData)r.Data).Address.Equals(AnswerAddress));
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

        var resolver = CreateResolver(internalClient, new Dictionary<string, string[]>
        {
            ["example"] = new[] { broad.ToString() },
            ["b.example"] = new[] { specific.ToString() }
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
        var resolver = CreateResolver(internalClient, new Dictionary<string, string[]>
        {
            ["nebula"] = new[] { NebulaForwarder.ToString() }
        });

        var result = await resolver.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("www.example.com")),
            CancellationToken.None);

        Assert.Null(result);
        Assert.Empty(internalClient.Calls);
    }

    [Fact]
    public async Task EmptyRoutesReturnsNull()
    {
        var internalClient = new CapturingInternalDomainClient((_, _) =>
            throw new InvalidOperationException("should not forward"));
        var resolver = CreateResolver(internalClient, new Dictionary<string, string[]>());

        var result = await resolver.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("nas.nebula")),
            CancellationToken.None);

        Assert.Null(result);
    }

    [Fact]
    public async Task DirectedUpstreamContextIsIgnored()
    {
        var internalClient = new CapturingInternalDomainClient((_, _) =>
            throw new InvalidOperationException("should not forward"));
        var resolver = CreateResolver(internalClient, new Dictionary<string, string[]>
        {
            ["nebula"] = new[] { NebulaForwarder.ToString() }
        });

        var result = await resolver.ProcessAsync(
            new DomainMessageContext(null, null, DomainMessage.CreateRequest("nas.nebula"))
            {
                UpstreamEndpoints = ImmutableArray.Create(NebulaForwarder)
            },
            CancellationToken.None);

        Assert.Null(result);
    }

    private static ForwardResolver CreateResolver(
        IInternalDomainClient internalClient,
        Dictionary<string, string[]> routes)
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
            new TestOptionsMonitor(configuration),
            internalClient,
            new AuthoritativeZoneStore(),
            NullLogger<ForwardResolver>.Instance);
    }

    private sealed class TestOptionsMonitor : IOptionsMonitor<DnsConfiguration>
    {
        public TestOptionsMonitor(DnsConfiguration current) => CurrentValue = current;
        public DnsConfiguration CurrentValue { get; }
        public DnsConfiguration Get(string? name) => CurrentValue;
        public IDisposable? OnChange(Action<DnsConfiguration, string?> listener) => null;
    }

    private sealed class CapturingInternalDomainClient : IInternalDomainClient
    {
        private readonly Func<DomainMessage, ImmutableArray<IPEndPoint>, DomainMessage> _handler;

        public CapturingInternalDomainClient(
            Func<DomainMessage, ImmutableArray<IPEndPoint>, DomainMessage> handler)
        {
            _handler = handler;
        }

        public List<string> Calls { get; } = new();

        public ValueTask<DomainMessage> SendAsync(DomainMessage message, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public ValueTask<DomainMessage> SendAsync(
            DomainMessageContext parentContext,
            DomainMessage message,
            CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public ValueTask<DomainMessage> SendAsync(
            DomainMessageContext parentContext,
            DomainMessage message,
            ImmutableArray<IPEndPoint> upstreamEndpoints,
            CancellationToken cancellationToken)
        {
            Calls.Add($"{message.Questions[0].Name}/{message.Questions[0].Type}");
            return ValueTask.FromResult(_handler(message, upstreamEndpoints));
        }
    }
}
