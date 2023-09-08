using System.Net;

using Dhcpr.Dns.Core.Resolvers.Resolvers.Abstractions;

using DNS.Client.RequestResolver;

namespace Dhcpr.Dns.Core.Resolvers.Caching;

public interface IResolverCache
{
    T GetResolver<T>(IPEndPoint endPoint, Func<IPEndPoint, T> createResolverCallback) where T : IRequestResolver;
    public TOuter GetResolver<TOuter, TInner>
    (
        IEnumerable<IPEndPoint> endPoints,
        Func<IEnumerable<IRequestResolver>, TOuter> createMultiResolver,
        Func<IPEndPoint, TInner> createInnerResolver
    )
        where TOuter : MultiResolver
        where TInner : IRequestResolver;
}