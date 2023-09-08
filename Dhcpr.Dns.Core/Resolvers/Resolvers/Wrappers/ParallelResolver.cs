using System.Diagnostics.CodeAnalysis;

using Dhcpr.Core;
using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Resolvers.Resolvers.Abstractions;

using DNS.Client.RequestResolver;
using DNS.Protocol;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Wrappers;

public sealed class ParallelResolver : MultiResolver, IParallelDnsResolver
{
    private const int ConcurrencyLimit = 4;

    public ParallelResolver(IEnumerable<IRequestResolver> resolvers)
    {
        AddResolvers(resolvers.ToArray());
    }

    private async Task<IResponse?> ExecuteResolversWithConcurrencyLimitAsync(IRequest request,
        CancellationToken cancellationToken)
    {
        using var resolvers = Resolvers;
        using var tasks = ListPool<Task<IResponse?>>.Default.Get();
        using var tokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        while (true)
        {
            if (Resolvers.Count == 0 || tasks.Count >= ConcurrencyLimit || tasks.Any(i => i.IsCompleted))
            {
                if (tasks.Count == 0) return null;
                var completed = await Task.WhenAny(tasks);
                tasks.Remove(completed);
                var result = await completed;
                if (result is null) continue;
                tokenSource.Cancel();
                await Task.WhenAll(tasks);
                return result;
            }

            var nextResolver = Resolvers[^1];
            Resolvers.RemoveAt(Resolvers.Count - 1);
            tasks.Add(nextResolver.Resolve(request, tokenSource.Token).OperationCancelledToNull()
                .ConvertExceptionsToNull());
        }
    }

    public override async Task<IResponse?> Resolve(IRequest request,
        CancellationToken cancellationToken = new CancellationToken())
    {
        var cancellationTokenSource = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);

        var result = await ExecuteResolversWithConcurrencyLimitAsync(request, cancellationTokenSource.Token);

        if (result is not null)
            return result;

        var nxDomainResponse = Response.FromRequest(request);
        nxDomainResponse.ResponseCode = ResponseCode.NameError;
        return nxDomainResponse;
    }
}