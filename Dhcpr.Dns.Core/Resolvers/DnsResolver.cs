using DNS.Protocol;

using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core;

public sealed class DnsResolver : IDnsResolver, IDisposable
{
    private readonly IRootResolver _rootResolver;
    private long _useParallelResolver;
    private readonly IDisposable? _configChangeSubscription;
    private readonly Func<IRequest, CancellationToken, Task<IResponse?>> _parallelMethod;
    private readonly Func<IRequest, CancellationToken, Task<IResponse?>> _sequentalMethod;

    private Func<IRequest, CancellationToken, Task<IResponse?>> SelectedMethod =>
        UseParallelResolver ? _parallelMethod : _sequentalMethod;

    public DnsResolver(IOptionsMonitor<DnsConfiguration> configuration, IParallelDnsResolver parallelDnsResolver,
        ISequentialDnsResolver sequentialDnsResolver, IRootResolver rootResolver)
    {
        _rootResolver = rootResolver;
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
        var result = await SelectedMethod(request, cancellationToken).ConfigureAwait(false);
        if (result is not null and not { ResponseCode: ResponseCode.NameError })
        {
            return result;
        }

        result = await _rootResolver.Resolve(request, cancellationToken).ConfigureAwait(false);
        return result;
    }


    public void Dispose()
    {
        _configChangeSubscription?.Dispose();
    }
}