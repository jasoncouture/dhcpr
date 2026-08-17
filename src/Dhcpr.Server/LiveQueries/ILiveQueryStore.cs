using System.Collections.Immutable;
using System.Threading.Channels;

using Dhcpr.Dns.Core.Protocol.Processing;

namespace Dhcpr.Server.LiveQueries;

public interface ILiveQueryStore
{
    ImmutableArray<DnsQueryEvent> GetSnapshot();
    (ChannelReader<DnsQueryEvent> Reader, IDisposable Subscription) Subscribe();
}
