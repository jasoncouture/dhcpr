using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;

using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Files;

public class BindFileResolver : IDomainMessageMiddleware
{
    private readonly IOptionsMonitor<BindFileConfiguration> _optionsMonitor;

    public BindFileResolver(IOptionsMonitor<BindFileConfiguration> optionsMonitor)
    {
        _optionsMonitor = optionsMonitor;
    }

    public ValueTask<DomainMessage?> ProcessAsync(DomainMessageContext context, CancellationToken cancellationToken)
    {
        throw new NotImplementedException();
    }

    public int Priority => 100;
}