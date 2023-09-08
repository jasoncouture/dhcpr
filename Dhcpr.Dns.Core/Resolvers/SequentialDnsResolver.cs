using Dhcpr.Core;

using DNS.Protocol;

namespace Dhcpr.Dns.Core.Resolvers;

public sealed class SequentialDnsResolver : MultiResolver, ISequentialDnsResolver
{
    public override async Task<IResponse?> Resolve(IRequest request, CancellationToken cancellationToken = new CancellationToken())
    {
        using var cancellationTokenSource =
            CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        using var resolvers = Resolvers;
        foreach (var resolver in resolvers)
        {
            var result = await resolver.Resolve(request, cancellationTokenSource.Token).OperationCancelledToNull().ConvertExceptionsToNull().ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();

            if (result is not null and { ResponseCode: ResponseCode.NameError or ResponseCode.NoError }) return result;
        }

        return null;
    }
}