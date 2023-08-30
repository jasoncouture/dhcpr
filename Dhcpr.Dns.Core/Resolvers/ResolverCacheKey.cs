using System.Net;

using DNS.Client.RequestResolver;

namespace Dhcpr.Dns.Core.Resolvers;

public record struct ResolverCacheKey(IPEndPoint EndPoint, Type ResolverType)
{
    public static ResolverCacheKey Create<T>(IPEndPoint endPoint) where T : IRequestResolver
    {
        return new ResolverCacheKey(endPoint, typeof(T));
    }
}