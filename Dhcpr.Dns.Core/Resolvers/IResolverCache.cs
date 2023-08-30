﻿using System.Net;

using DNS.Client.RequestResolver;

namespace Dhcpr.Dns.Core;

public interface IResolverCache
{
    T GetResolver<T>(IPEndPoint endPoint, Func<IPEndPoint, T> createResolverCallback) where T : IRequestResolver;

    public TOuter GetMultiResolver<TOuter, TInner>
    (
        IEnumerable<IPEndPoint> endPoints,
        Func<IEnumerable<IRequestResolver>, TOuter> createMultiResolver,
        Func<IPEndPoint, TInner> createInnerResolver
    )
        where TOuter : MultiResolver
        where TInner : IRequestResolver;
}