using System.Collections.Immutable;
using System.Net;

using Dhcpr.Core;

using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.RootZone;

public sealed class RootServerTips : IRootServerTips
{
    private readonly IOptionsMonitor<RootServerConfiguration> _options;
    private ImmutableArray<IPEndPoint> _downloadedTips = ImmutableArray<IPEndPoint>.Empty;

    public RootServerTips(IOptionsMonitor<RootServerConfiguration> options)
    {
        _options = options;
    }

    public ImmutableArray<IPEndPoint> GetEndpoints()
    {
        var fromConfig = _options.CurrentValue.Addresses
            .Select(static i => i.GetEndPoint(53))
            .Cast<IPEndPoint>()
            .ToImmutableArray();

        if (fromConfig.Length > 0)
            return fromConfig;

        return _downloadedTips;
    }

    public void SetDownloadedTips(IEnumerable<IPAddress> addresses)
    {
        _downloadedTips = addresses
            .Select(static a => new IPEndPoint(a, 53))
            .ToImmutableArray();
    }
}
