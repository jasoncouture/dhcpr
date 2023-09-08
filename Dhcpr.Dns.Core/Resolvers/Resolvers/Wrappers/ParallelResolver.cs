using System.Diagnostics.CodeAnalysis;

using Dhcpr.Core;
using Dhcpr.Core.Linq;

using DNS.Client.RequestResolver;
using DNS.Protocol;

namespace Dhcpr.Dns.Core.Resolvers;

public sealed class ParallelResolver : MultiResolver, IParallelDnsResolver
{
    public ParallelResolver(IEnumerable<IRequestResolver> resolvers)
    {
        AddResolvers(resolvers.ToArray());
    }

    private PooledList<Task<IResponse?>> GetResolverTasks(IRequest request, CancellationToken cancellationToken)
    {
        using var resolvers = Resolvers;
        return resolvers
            .Select(
                [SuppressMessage("ReSharper", "AccessToDisposedClosure",
                    Justification = "Enumerable is enumerated immediately.")]
                async (i) =>
                {
                    try
                    {
                        return await i.Resolve(request, cancellationToken)
                            .ConfigureAwait(false);
                    }
                    catch (OperationCanceledException)
                    {
                        return null;
                    }
                })
            .Select(async i =>
                // Make 100% sure the cancellation token is respected
                await i.WaitAsync(cancellationToken)
                    .ConvertExceptionsToNull()
                    .ConfigureAwait(false))
            .ToPooledList();
    }

    public override async Task<IResponse?> Resolve(IRequest request,
        CancellationToken cancellationToken = new CancellationToken())
    {
        var cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        using var tasks = GetResolverTasks(request, cancellationTokenSource.Token);

        while (tasks.Count > 0)
        {
            var completed = await Task.WhenAny(tasks).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            tasks.Remove(completed);
            var response = await completed.ConfigureAwait(false);
            if (response is null or not { ResponseCode: ResponseCode.NameError or ResponseCode.NoError })
                continue;
            cancellationTokenSource.Cancel();
            return response;
        }

        var nxDomainResponse = Response.FromRequest(request);
        nxDomainResponse.ResponseCode = ResponseCode.NameError;
        return nxDomainResponse;
    }
}