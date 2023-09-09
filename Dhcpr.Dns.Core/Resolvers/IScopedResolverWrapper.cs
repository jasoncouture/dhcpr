using DNS.Client.RequestResolver;

namespace Dhcpr.Dns.Core.Resolvers;

public interface IScopedResolverWrapper<T> : IRequestResolver where T : IRequestResolver
{
}