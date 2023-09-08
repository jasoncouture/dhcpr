namespace Dhcpr.Dns.Core;

public record struct MultiResolverCacheKey(ResolverCacheKey[] InnerCacheKeys, Type ResolverType);