using System.Diagnostics.CodeAnalysis;

using DNS.Protocol;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

public interface IDnsCache
{
    bool TryGetCachedResponse(IRequest request, [NotNullWhen(true)] out IResponse? response);
    void TryAddCacheEntry(IRequest request, IResponse response);
}