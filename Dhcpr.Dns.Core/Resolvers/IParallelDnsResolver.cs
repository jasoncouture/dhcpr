using DNS.Client.RequestResolver;

namespace Dhcpr.Dns.Core.Resolvers;

public interface IParallelDnsResolver : IRequestResolver, IMultiResolver
{
}