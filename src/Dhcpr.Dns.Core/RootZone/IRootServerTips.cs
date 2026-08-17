using System.Collections.Immutable;
using System.Net;

namespace Dhcpr.Dns.Core.RootZone;

public interface IRootServerTips
{
    ImmutableArray<IPEndPoint> GetEndpoints();
    void SetDownloadedTips(IEnumerable<IPAddress> addresses);
}
