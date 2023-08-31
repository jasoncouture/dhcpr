using DNS.Client.RequestResolver;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

public record struct CachedResolverCacheKey(Type Type, int Instance)
{
    public static CachedResolverCacheKey FromInstance(IRequestResolver requestResolver)
    {
        return new CachedResolverCacheKey(requestResolver.GetType(), requestResolver.GetHashCode());
    }
}