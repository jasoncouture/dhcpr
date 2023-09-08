using System.Diagnostics.CodeAnalysis;

using DNS.Protocol;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

public interface IDnsCache
{
    ValueTask<IResponse?> TryGetCachedResponseAsync(
        IRequest request, 
        CancellationToken cancellationToken
        );

    ValueTask TryAddCacheEntryAsync(IRequest request, IResponse response, CancellationToken cancellationToken = default);
}