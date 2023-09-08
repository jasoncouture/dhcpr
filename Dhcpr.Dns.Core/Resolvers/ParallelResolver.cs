using System.Diagnostics.CodeAnalysis;
using Dhcpr.Core;
using DNS.Client.RequestResolver;
using DNS.Protocol;

using Microsoft.Extensions.Primitives;

namespace Dhcpr.Dns.Core;

public sealed class ParallelResolver : MultiResolver, IParallelDnsResolver
{
    public ParallelResolver(IEnumerable<IRequestResolver> resolvers)
    {
        AddResolvers(resolvers.ToArray());
    }

    private IEnumerable<Task<IResponse?>> GetResolverTasks(IRequest request, CancellationToken cancellationToken)
    {
        ;
        using var resolvers = Resolvers;
        return resolvers
            .Select(
                [SuppressMessage("ReSharper", "AccessToDisposedClosure",
                    Justification = "Enumerable is enumerated immediately.")]
                async (i) =>
                {
                    // Yield to force a transition to async, so we can capture even synchronous
                    // operation cancelled exceptions.
                    await Task.Yield();
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
                    .ConfigureAwait(false));
    }

    public override async Task<IResponse?> Resolve(IRequest request,
        CancellationToken cancellationToken = new CancellationToken())
    {
        var cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        using var tasks = GetResolverTasks(request, cancellationTokenSource.Token).ToPooledList();

        while (tasks.Count > 0)
        {
            var completed = await Task.WhenAny(tasks).ConfigureAwait(false);
            cancellationToken.ThrowIfCancellationRequested();
            tasks.Remove(completed);
            var response = await completed.ConfigureAwait(false);
            if (response is null or { ResponseCode: ResponseCode.NameError } or
                { ResponseCode: ResponseCode.ServerFailure }) continue;
            cancellationTokenSource.Cancel();
            return response;
        }

        var nxDomainResponse = Response.FromRequest(request);
        nxDomainResponse.ResponseCode = ResponseCode.NameError;
        return nxDomainResponse;
    }
}