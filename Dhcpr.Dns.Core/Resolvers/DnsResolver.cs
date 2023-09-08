using DNS.Protocol;

using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core;

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