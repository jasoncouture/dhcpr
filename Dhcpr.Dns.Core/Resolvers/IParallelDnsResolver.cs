using DNS.Client.RequestResolver;

namespace Dhcpr.Dns.Core;

public interface IParallelDnsResolver : IRequestResolver, IMultiResolver
{
}