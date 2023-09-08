using Dhcpr.Dns.Core.Resolvers.Caching;

using DNS.Protocol;

namespace Dhcpr.Dns.Core;

public sealed record DnsCacheMessage(QueryCacheKey Key, IResponse? Response, TimeSpan TimeToLive, bool Invalidate);