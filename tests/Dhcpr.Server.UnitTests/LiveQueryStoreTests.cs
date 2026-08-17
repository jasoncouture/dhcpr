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
            new IPEndPoint(IPAddress.Loopback, 53000 + index),
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
