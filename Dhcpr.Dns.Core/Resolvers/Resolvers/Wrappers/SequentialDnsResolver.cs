using System.Net;

using Dhcpr.Core;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Abstractions;

using DNS.Client.RequestResolver;
using DNS.Protocol;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Wrappers;

public sealed class SequentialDnsResolver : MultiResolver, ISequentialDnsResolver
{
    public SequentialDnsResolver(IEnumerable<IRequestResolver> resolvers)
    {
        ReplaceResolvers(resolvers.ToArray());
    }

    public override async Task<IResponse?> Resolve(IRequest request,
        CancellationToken cancellationToken = new CancellationToken())
    {
        using var cancellationTokenSource =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var resolvers = Resolvers;
        foreach (var resolver in resolvers)
        {
            var result = await resolver.Resolve(request, cancellationTokenSource.Token).OperationCancelledToNull()
                .ConvertExceptionsToNull();
            cancellationToken.ThrowIfCancellationRequested();

            if (result is not null) return result;
        }

        return null;
    }
}