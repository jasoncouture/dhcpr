namespace Dhcpr.Dns.Core.Resolvers;

public record struct MultiResolverCacheKey(ResolverCacheKey[] InnerCacheKeys, Type ResolverType);