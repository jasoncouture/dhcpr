using Microsoft.Extensions.DependencyInjection;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed class DnsQueryPipeline : IDnsQueryPipeline
{
    private readonly IServiceScopeFactory _scopes;

    public DnsQueryPipeline(IServiceScopeFactory scopes)
    {
        _scopes = scopes;
    }

    public async ValueTask<DomainMessage?> ExecuteAsync(
        DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        await using var scope = _scopes.CreateAsyncScope();
        var runner = scope.ServiceProvider.GetRequiredService<DomainMessageContextMessageProcessor>();
        return await runner.ExecuteAsync(context, cancellationToken).ConfigureAwait(false);
    }
}
