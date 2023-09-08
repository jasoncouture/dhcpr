using System.Net;

using DNS.Client.RequestResolver;

namespace Dhcpr.Dns.Core.Resolvers;

public interface IResolverCache
{
    T GetResolver<T>(IPEndPoint endPoint, Func<IPEndPoint, T> createResolverCallback) where T : IRequestResolver;
    ICachedResolver GetCacheForResolver(IRequestResolver resolver);
    public TOuter GetResolver<TOuter, TInner>
    (
        IEnumerable<IPEndPoint> endPoints,
        Func<IEnumerable<IRequestResolver>, TOuter> createMultiResolver,
        Func<IPEndPoint, TInner> createInnerResolver
    )
        where TOuter : MultiResolver
        where TInner : IRequestResolver;
}