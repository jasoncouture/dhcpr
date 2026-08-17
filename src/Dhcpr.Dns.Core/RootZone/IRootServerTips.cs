using System.Collections.Immutable;
using System.Net;

namespace Dhcpr.Dns.Core.RootZone;

public interface IRootServerTips
{
    /// <summary>
    /// Returns configured root addresses, or the last downloaded hint set, on port 53.
    /// </summary>
    ImmutableArray<IPEndPoint> GetEndpoints();

    /// <summary>
    /// Replaces the downloaded hint set with <paramref name="addresses"/> on port 53.
    /// </summary>
    void SetDownloadedTips(IEnumerable<IPAddress> addresses);
}
