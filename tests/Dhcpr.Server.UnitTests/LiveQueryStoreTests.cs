using System.Net;

using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Server.LiveQueries;

using MessagePipe;

using NSubstitute;

namespace Dhcpr.Server.UnitTests;

public class LiveQueryStoreTests
{
    [Fact]
    public async Task SnapshotRetainsNewestFirstAndCapsCapacity()
    {
        var subscriber = Substitute.For<IAsyncSubscriber<DnsQueryEvent>>();
        await using var store = new LiveQueryStore(subscriber);

        for (var i = 0; i < LiveQueryStore.SnapshotCapacity + 25; i++)
            await store.HandleAsync(CreateEvent(i), CancellationToken.None);

        var snapshot = store.GetSnapshot();
        Assert.Equal(LiveQueryStore.SnapshotCapacity, snapshot.Length);
        Assert.Equal(LiveQueryStore.SnapshotCapacity + 24, ParseIndex(snapshot[0]));
        Assert.Equal(25, ParseIndex(snapshot[^1]));
    }

    [Fact]
    public async Task SubscribeReceivesFanOutEvents()
    {
        var subscriber = Substitute.For<IAsyncSubscriber<DnsQueryEvent>>();
        await using var store = new LiveQueryStore(subscriber);
        var (reader, subscription) = store.Subscribe();
        using (subscription)
        {
            var evt = CreateEvent(7);
            await store.HandleAsync(evt, CancellationToken.None);

            using var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            var received = await reader.ReadAsync(cancellationTokenSource.Token);
            Assert.Equal(evt.Id, received.Id);
            Assert.Equal("q-7.example", received.Name);
        }
    }

    [Fact]
    public async Task HealthCheckProbesAreNotRetainedOrFannedOut()
    {
        var subscriber = Substitute.For<IAsyncSubscriber<DnsQueryEvent>>();
        await using var store = new LiveQueryStore(subscriber);
        var (reader, subscription) = store.Subscribe();
        using (subscription)
        {
            var probe = CreateEvent(1) with
            {
                Client = new IPEndPoint(IPAddress.Loopback, 0)
            };
            var ipv6Probe = CreateEvent(2) with
            {
                Client = new IPEndPoint(IPAddress.IPv6Loopback, 0)
            };
            var loopbackClient = CreateEvent(3) with
            {
                Client = new IPEndPoint(IPAddress.Loopback, 43767)
            };
            var external = CreateEvent(4);

            await store.HandleAsync(probe, CancellationToken.None);
            await store.HandleAsync(ipv6Probe, CancellationToken.None);
            await store.HandleAsync(loopbackClient, CancellationToken.None);
            await store.HandleAsync(external, CancellationToken.None);

            var snapshot = store.GetSnapshot();
            Assert.Equal(2, snapshot.Length);
            Assert.Equal(external.Id, snapshot[0].Id);
            Assert.Equal(loopbackClient.Id, snapshot[1].Id);

            using var cancellationTokenSource = new CancellationTokenSource(TimeSpan.FromSeconds(2));
            Assert.Equal(loopbackClient.Id, (await reader.ReadAsync(cancellationTokenSource.Token)).Id);
            Assert.Equal(external.Id, (await reader.ReadAsync(cancellationTokenSource.Token)).Id);
            Assert.False(reader.TryRead(out _));
        }
    }

    [Fact]
    public async Task DropOldestWhenSubscriberFallsBehind()
    {
        var subscriber = Substitute.For<IAsyncSubscriber<DnsQueryEvent>>();
        await using var store = new LiveQueryStore(subscriber);
        var (reader, subscription) = store.Subscribe();
        using (subscription)
        {
            for (var i = 0; i < LiveQueryStore.FanOutCapacity + 50; i++)
                await store.HandleAsync(CreateEvent(i), CancellationToken.None);

            var count = 0;
            while (reader.TryRead(out _))
                count++;

            Assert.True(count <= LiveQueryStore.FanOutCapacity);
            Assert.True(count >= LiveQueryStore.FanOutCapacity - 1);
        }
    }

    private static DnsQueryEvent CreateEvent(int index)
        => new(
            Guid.CreateVersion7(),
            DateTimeOffset.UtcNow,
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 53000 + index),
            new IPEndPoint(IPAddress.Loopback, 53),
            $"q-{index}.example",
            DomainRecordType.A,
            DomainResponseCode.NoError,
            CacheHit: false,
            Answers: "127.0.0.1",
            Middleware: "Test");

    private static int ParseIndex(DnsQueryEvent evt)
        => int.Parse(evt.Name.AsSpan("q-".Length, evt.Name.IndexOf('.') - "q-".Length));
}
