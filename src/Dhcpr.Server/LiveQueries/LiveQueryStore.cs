using System.Collections.Concurrent;
using System.Collections.Immutable;
using System.Net;
using System.Threading.Channels;

using Dhcpr.Dns.Core.Protocol.Processing;

using MessagePipe;

using Microsoft.Extensions.Hosting;

namespace Dhcpr.Server.LiveQueries;

/// <summary>
/// Retains a ring of recent <see cref="DnsQueryEvent"/>s and fans them out per Blazor circuit
/// via DropOldest channels so slow UI never back-pressures DNS.
/// </summary>
public sealed class LiveQueryStore : ILiveQueryStore, IHostedService, IAsyncMessageHandler<DnsQueryEvent>, IAsyncDisposable
{
    public const int SnapshotCapacity = 250;
    public const int FanOutCapacity = 1000;

    private readonly IAsyncSubscriber<DnsQueryEvent> _subscriber;
    private readonly object _ringLock = new();
    private readonly LinkedList<DnsQueryEvent> _ring = new();
    private readonly ConcurrentDictionary<Guid, ChannelWriter<DnsQueryEvent>> _subscribers = new();

    private IDisposable? _subscription;

    public LiveQueryStore(IAsyncSubscriber<DnsQueryEvent> subscriber)
    {
        _subscriber = subscriber;
    }

    public ImmutableArray<DnsQueryEvent> GetSnapshot()
    {
        lock (_ringLock)
            return _ring.ToImmutableArray();
    }

    /// <summary>
    /// Creates a per-circuit reader. Dispose the returned subscription to unregister.
    /// </summary>
    public (ChannelReader<DnsQueryEvent> Reader, IDisposable Subscription) Subscribe()
    {
        var id = Guid.NewGuid();
        var channel = Channel.CreateBounded<DnsQueryEvent>(
            new BoundedChannelOptions(FanOutCapacity)
            {
                FullMode = BoundedChannelFullMode.DropOldest,
                SingleReader = true,
                SingleWriter = false
            });

        _subscribers[id] = channel.Writer;
        return (channel.Reader, new Subscription(this, id, channel.Writer));
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await Task.Yield();
        _subscription = _subscriber.Subscribe(this);
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        await Task.Yield();
        _subscription?.Dispose();
        _subscription = null;
        foreach (var writer in _subscribers.Values)
            writer.TryComplete();
        _subscribers.Clear();
    }

    public async ValueTask HandleAsync(DnsQueryEvent message, CancellationToken cancellationToken)
    {
        await Task.Yield();
        if (IsHealthCheckProbe(message))
            return;

        lock (_ringLock)
        {
            _ring.AddFirst(message);
            while (_ring.Count > SnapshotCapacity)
                _ring.RemoveLast();
        }

        foreach (var writer in _subscribers.Values)
            writer.TryWrite(message);
    }

    // Health checks use 127.0.0.1:0 / [::1]:0. Real loopback clients have an ephemeral port.
    private static bool IsHealthCheckProbe(DnsQueryEvent evt) =>
        evt.Client is { Port: 0, Address: { } address } && IPAddress.IsLoopback(address);

    public async ValueTask DisposeAsync()
    {
        await Task.Yield();
        _subscription?.Dispose();
        _subscription = null;
        foreach (var writer in _subscribers.Values)
            writer.TryComplete();
        _subscribers.Clear();
    }

    private void Unsubscribe(Guid id, ChannelWriter<DnsQueryEvent> writer)
    {
        if (_subscribers.TryRemove(id, out _))
            writer.TryComplete();
    }

    private sealed class Subscription : IDisposable
    {
        private readonly LiveQueryStore _store;
        private readonly Guid _id;
        private readonly ChannelWriter<DnsQueryEvent> _writer;
        private int _disposed;

        public Subscription(LiveQueryStore store, Guid id, ChannelWriter<DnsQueryEvent> writer)
        {
            _store = store;
            _id = id;
            _writer = writer;
        }

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
                return;
            _store.Unsubscribe(_id, _writer);
        }
    }
}
