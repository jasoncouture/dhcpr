using System.Collections.Immutable;
using System.Threading.Channels;

using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Server.LiveQueries;

public interface ILiveQueryStore
{
    /// <summary>
    /// Returns a copy of the recent query ring.
    /// </summary>
    ImmutableArray<DnsQueryEvent> GetSnapshot();

    /// <summary>
    /// Subscribes to live query events. Dispose the returned subscription to unregister.
    /// </summary>
    (ChannelReader<DnsQueryEvent> Reader, IDisposable Subscription) Subscribe();
}
