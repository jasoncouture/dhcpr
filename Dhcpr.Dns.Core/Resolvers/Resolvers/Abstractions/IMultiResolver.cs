﻿using DNS.Client.RequestResolver;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Abstractions;

public interface IMultiResolver : IRequestResolver
{
    void ReplaceResolvers(params IRequestResolver[] resolvers);
    void AddResolvers(params IRequestResolver[] resolvers);
    void AddResolver(IRequestResolver resolver);
    void RemoveResolver(IRequestResolver resolver);
}