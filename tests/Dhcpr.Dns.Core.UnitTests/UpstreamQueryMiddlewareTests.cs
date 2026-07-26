using System.Collections.Immutable;
using System.Net;
using System.Net.Sockets;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;

using NSubstitute;

namespace Dhcpr.Dns.Core.UnitTests;

public class UpstreamQueryMiddlewareTests
{
    [Fact]
    public async Task TransportFailureOnFirstBatchTriesRemainingEndpoints()
    {
        var unreachable1 = new IPEndPoint(IPAddress.Parse("2001:db8::1"), 53);
        var unreachable2 = new IPEndPoint(IPAddress.Parse("2001:db8::2"), 53);
        var unreachable3 = new IPEndPoint(IPAddress.Parse("2001:db8::3"), 53);
        var reachable = new IPEndPoint(IPAddress.Parse("1.2.3.4"), 53);
        var answer = IPAddress.Parse("9.9.9.9");
        var unreachable = new HashSet<IPEndPoint> { unreachable1, unreachable2, unreachable3 };

        var factory = Substitute.For<IDomainClientFactory>();
        factory.GetParallelDomainClient(Arg.Any<IEnumerable<DomainClientOptions>>(), Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                var options = callInfo.ArgAt<IEnumerable<DomainClientOptions>>(0).ToArray();
                var clients = options.Select(o => CreateClient(o.EndPoint, unreachable, answer)).ToArray();
                return new ValueTask<IDomainClient>(new DomainClientParallelWrapper(clients));
            });

        var middleware = new UpstreamQueryMiddleware(factory, CreateEdns());
        var request = DomainMessage.CreateRequest("example.com");
        // First batch (3) is all unreachable; second batch contains the reachable peer.
        var context = new DomainMessageContext(null, null, request)
        {
            UpstreamEndpoints = ImmutableArray.Create(unreachable1, unreachable2, unreachable3, reachable)
        };

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NoError, result!.Flags.ResponseCode);
        Assert.Contains(result.Records.Answers, r =>
            r.Type == DomainRecordType.A && ((IPAddressData)r.Data).Address.Equals(answer));
    }

    [Fact]
    public async Task SameBatchTransportFailureDoesNotPreventSiblingSuccess()
    {
        var unreachable = new IPEndPoint(IPAddress.Parse("2001:db8::1"), 53);
        var reachable = new IPEndPoint(IPAddress.Parse("1.2.3.4"), 53);
        var answer = IPAddress.Parse("9.9.9.9");

        var factory = Substitute.For<IDomainClientFactory>();
        factory.GetParallelDomainClient(Arg.Any<IEnumerable<DomainClientOptions>>(), Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                var options = callInfo.ArgAt<IEnumerable<DomainClientOptions>>(0).ToArray();
                var clients = options.Select(o =>
                    CreateClient(o.EndPoint, new HashSet<IPEndPoint> { unreachable }, answer)).ToArray();
                return new ValueTask<IDomainClient>(new DomainClientParallelWrapper(clients));
            });

        var middleware = new UpstreamQueryMiddleware(factory, CreateEdns());
        var request = DomainMessage.CreateRequest("example.com");
        var context = new DomainMessageContext(null, null, request)
        {
            UpstreamEndpoints = ImmutableArray.Create(unreachable, reachable)
        };

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NoError, result!.Flags.ResponseCode);
    }

    [Fact]
    public async Task ServFailOnlyAfterAllEndpointsExhausted()
    {
        var factory = Substitute.For<IDomainClientFactory>();
        factory.GetParallelDomainClient(Arg.Any<IEnumerable<DomainClientOptions>>(), Arg.Any<CancellationToken>())
            .Returns(_ =>
            {
                var client = Substitute.For<IDomainClient>();
                client.SendAsync(Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
                    .Returns(_ => new ValueTask<DomainMessage>(
                        Task.FromException<DomainMessage>(
                            new SocketException((int)SocketError.NetworkUnreachable))));
                return new ValueTask<IDomainClient>(client);
            });

        var middleware = new UpstreamQueryMiddleware(factory, CreateEdns());
        var request = DomainMessage.CreateRequest("example.com");
        var context = new DomainMessageContext(null, null, request)
        {
            UpstreamEndpoints = ImmutableArray.Create(
                new IPEndPoint(IPAddress.Parse("2001:db8::1"), 53),
                new IPEndPoint(IPAddress.Parse("2001:db8::2"), 53))
        };

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.ServerFailure, result!.Flags.ResponseCode);
    }

    [Fact]
    public async Task NameErrorOnFirstBatchTriesRemainingEndpoints()
    {
        var lying = new IPEndPoint(IPAddress.Parse("2001:db8::1"), 53);
        var lying2 = new IPEndPoint(IPAddress.Parse("2001:db8::2"), 53);
        var lying3 = new IPEndPoint(IPAddress.Parse("2001:db8::3"), 53);
        var honest = new IPEndPoint(IPAddress.Parse("1.2.3.4"), 53);
        var answer = IPAddress.Parse("9.9.9.9");
        var liars = new HashSet<IPEndPoint> { lying, lying2, lying3 };

        var factory = Substitute.For<IDomainClientFactory>();
        factory.GetParallelDomainClient(Arg.Any<IEnumerable<DomainClientOptions>>(), Arg.Any<CancellationToken>())
            .Returns(callInfo =>
            {
                var options = callInfo.ArgAt<IEnumerable<DomainClientOptions>>(0).ToArray();
                var clients = options.Select(o => CreateClientOrNameError(o.EndPoint, liars, answer)).ToArray();
                return new ValueTask<IDomainClient>(new DomainClientParallelWrapper(clients));
            });

        var middleware = new UpstreamQueryMiddleware(factory, CreateEdns());
        var request = DomainMessage.CreateRequest("example.com");
        var context = new DomainMessageContext(null, null, request)
        {
            UpstreamEndpoints = ImmutableArray.Create(lying, lying2, lying3, honest)
        };

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NoError, result!.Flags.ResponseCode);
        Assert.Contains(result.Records.Answers, r =>
            r.Type == DomainRecordType.A && ((IPAddressData)r.Data).Address.Equals(answer));
    }

    [Fact]
    public async Task NameErrorAfterAllEndpointsReturnsNameError()
    {
        var factory = Substitute.For<IDomainClientFactory>();
        factory.GetParallelDomainClient(Arg.Any<IEnumerable<DomainClientOptions>>(), Arg.Any<CancellationToken>())
            .Returns(_ =>
            {
                var client = Substitute.For<IDomainClient>();
                client.SendAsync(Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
                    .Returns(call => new ValueTask<DomainMessage>(DomainMessage.CreateResponse(
                        call.ArgAt<DomainMessage>(0),
                        DomainResourceRecords.Empty,
                        DomainResponseCode.NameError)));
                return new ValueTask<IDomainClient>(client);
            });

        var middleware = new UpstreamQueryMiddleware(factory, CreateEdns());
        var request = DomainMessage.CreateRequest("missing.example");
        var context = new DomainMessageContext(null, null, request)
        {
            UpstreamEndpoints = ImmutableArray.Create(
                new IPEndPoint(IPAddress.Parse("2001:db8::1"), 53),
                new IPEndPoint(IPAddress.Parse("2001:db8::2"), 53))
        };

        var result = await middleware.ProcessAsync(context, CancellationToken.None);

        Assert.NotNull(result);
        Assert.Equal(DomainResponseCode.NameError, result!.Flags.ResponseCode);
    }

    private static IDomainClient CreateClientOrNameError(
        IPEndPoint endPoint,
        HashSet<IPEndPoint> nameErrorEndpoints,
        IPAddress answer)
    {
        var client = Substitute.For<IDomainClient>();
        if (nameErrorEndpoints.Contains(endPoint))
        {
            client.SendAsync(Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
                .Returns(call => new ValueTask<DomainMessage>(DomainMessage.CreateResponse(
                    call.ArgAt<DomainMessage>(0),
                    DomainResourceRecords.Empty,
                    DomainResponseCode.NameError)));
        }
        else
        {
            client.SendAsync(Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
                .Returns(call => new ValueTask<DomainMessage>(DomainMessage.CreateResponse(
                    call.ArgAt<DomainMessage>(0),
                    new[]
                    {
                        new DomainResourceRecord(
                            new DomainLabels("example.com"),
                            DomainRecordType.A,
                            DomainRecordClass.IN,
                            TimeSpan.FromSeconds(60),
                            new IPAddressData(answer))
                    },
                    responseCode: DomainResponseCode.NoError)));
        }

        return client;
    }

    private static IDomainClient CreateClient(
        IPEndPoint endPoint,
        HashSet<IPEndPoint> unreachable,
        IPAddress answer)
    {
        var client = Substitute.For<IDomainClient>();
        if (unreachable.Contains(endPoint))
        {
            client.SendAsync(Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
                .Returns(_ => new ValueTask<DomainMessage>(
                    Task.FromException<DomainMessage>(
                        new SocketException((int)SocketError.NetworkUnreachable))));
        }
        else
        {
            client.SendAsync(Arg.Any<DomainMessage>(), Arg.Any<CancellationToken>())
                .Returns(call => new ValueTask<DomainMessage>(DomainMessage.CreateResponse(
                    call.ArgAt<DomainMessage>(0),
                    new[]
                    {
                        new DomainResourceRecord(
                            new DomainLabels("example.com"),
                            DomainRecordType.A,
                            DomainRecordClass.IN,
                            TimeSpan.FromSeconds(60),
                            new IPAddressData(answer))
                    },
                    responseCode: DomainResponseCode.NoError)));
        }

        return client;
    }

    private static IEdnsProtocolService CreateEdns()
    {
        var edns = Substitute.For<IEdnsProtocolService>();
        edns.CreateOptRecord(Arg.Any<ushort>(), Arg.Any<bool>(), Arg.Any<byte>(), Arg.Any<byte>(), Arg.Any<OptionData?>())
            .Returns(_ => new DomainResourceRecord(
                DomainLabels.Empty,
                DomainRecordType.OPT,
                (DomainRecordClass)512,
                TimeSpan.Zero,
                new OptionData(ImmutableArray<EdnsOption>.Empty)));
        return edns;
    }
}
