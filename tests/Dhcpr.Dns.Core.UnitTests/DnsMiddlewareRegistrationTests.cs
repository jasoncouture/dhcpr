using Dhcpr.Dns.Core;
using Dhcpr.Dns.Core.Protocol.Processing;

using Microsoft.Extensions.DependencyInjection;

namespace Dhcpr.Dns.Core.UnitTests;

public class DnsMiddlewareRegistrationTests
{
    [Fact]
    public void AddDnsRegistersSingleMiddlewarePipeline()
    {
        var services = new ServiceCollection();
        services.AddDns();

        var middleware = services
            .Where(static d => d.ServiceType == typeof(IDomainMessageMiddleware) && !d.IsKeyedService)
            .ToList();

        Assert.Single(middleware);
    }
}
