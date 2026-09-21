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

    [Fact]
    public void AddDnsRegistersSingletonPipelineAndScopedRunner()
    {
        var services = new ServiceCollection();
        services.AddDns();

        var pipeline = Assert.Single(services, static d => d.ServiceType == typeof(IDnsQueryPipeline));
        Assert.Equal(ServiceLifetime.Singleton, pipeline.Lifetime);
        Assert.Equal(typeof(DnsQueryPipeline), pipeline.ImplementationType);

        var runner = Assert.Single(services, static d => d.ServiceType == typeof(DomainMessageContextMessageProcessor));
        Assert.Equal(ServiceLifetime.Scoped, runner.Lifetime);
    }
}
