﻿using DNS.Client.RequestResolver;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Abstractions;

public interface IParallelDnsResolver : IRequestResolver, IMultiResolver
{
}