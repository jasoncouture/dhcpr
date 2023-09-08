using System.Diagnostics.CodeAnalysis;
using Dhcpr.Core;
using DNS.Client.RequestResolver;
using DNS.Protocol;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace Dhcpr.Dns.Core;

public interface IDnsResolver : IRequestResolver
{
}

public interface IParallelDnsResolver : IRequestResolver
{
}

public interface ISequentialDnsResolver : IRequestResolver
{
}

public sealed class DnsResolver : IDnsResolver, IDisposable
{
    private long _useParallelResolver;
    private readonly IDisposable? _configChangeSubscription;
    private readonly Func<IRequest, CancellationToken, Task<IResponse?>> _parallelMethod;
    private readonly Func<IRequest, CancellationToken, Task<IResponse?>> _sequentalMethod;

    private Func<IRequest, CancellationToken, Task<IResponse?>> SelectedMethod =>
        UseParallelResolver ? _parallelMethod : _sequentalMethod;

    public DnsResolver(IOptionsMonitor<DnsConfiguration> configuration, IParallelDnsResolver parallelDnsResolver,
        ISequentialDnsResolver sequentialDnsResolver)
    {
        _configChangeSubscription = configuration.OnChange(OnConfigurationChanged);
        _parallelMethod = parallelDnsResolver.Resolve;
        _sequentalMethod = sequentialDnsResolver.Resolve;
        OnConfigurationChanged(configuration.CurrentValue);
    }

    private bool UseParallelResolver => _useParallelResolver == 1;

    private void OnConfigurationChanged(DnsConfiguration configuration)
    {
        Interlocked.Exchange(ref _useParallelResolver, configuration.UseParallelResolver ? 1 : 0);
    }

    public async Task<IResponse?> Resolve(IRequest request,
        CancellationToken cancellationToken = new CancellationToken())
    {
        return await SelectedMethod(request, cancellationToken).ConfigureAwait(false);
    }


    public void Dispose()
    {
        _configChangeSubscription?.Dispose();
    }
}

public sealed class ParallelResolver : MultiResolver, IParallelDnsResolver
{
    public ParallelResolver(params IRequestResolver[] resolvers)
    {
        AddResolvers(resolvers);
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