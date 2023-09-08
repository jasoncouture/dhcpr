namespace Dhcpr.Dns.Core.Resolvers.Caching;

public record struct MultiResolverCacheKey(ResolverCacheKey[] InnerCacheKeys, Type ResolverType);