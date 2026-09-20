using Dhcpr.Dns.Core;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Server;

using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

using NSubstitute;

namespace Dhcpr.Server.UnitTests;

public class DnsListenersHealthCheckTests
{
    [Fact]
    public async Task UnhealthyWhenDnsSocketsAreNotBound()
    {
        var dns = new DnsListenerReadiness();
        dns.SetExpected(["udp://127.0.0.1:53"]);
        var check = Create(dns, tlsEnabled: false);

        var result = await check.CheckHealthAsync(new HealthCheckContext(), CancellationToken.None);

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Contains("udp://127.0.0.1:53", result.Description);
    }

    [Fact]
    public async Task UnhealthyWhenTlsEnabledAndHttpsIsMissing()
    {
        var dns = new DnsListenerReadiness();
        dns.SetExpected(["tls://127.0.0.1:853"]);
        dns.MarkBound("tls://127.0.0.1:853");
        var check = Create(dns, tlsEnabled: true, httpsAddresses: ["http://[::]:8080"]);

        var result = await check.CheckHealthAsync(new HealthCheckContext(), CancellationToken.None);

        Assert.Equal(HealthStatus.Unhealthy, result.Status);
        Assert.Contains("HTTPS", result.Description);
    }

    [Fact]
    public async Task HealthyWhenDnsAndHttpsAreListening()
    {
        var dns = new DnsListenerReadiness();
        dns.SetExpected(["udp://127.0.0.1:53", "tls://127.0.0.1:853"]);
        dns.MarkBound("udp://127.0.0.1:53");
        dns.MarkBound("tls://127.0.0.1:853");
        var check = Create(dns, tlsEnabled: true, httpsAddresses: ["https://[::]:443"]);

        var result = await check.CheckHealthAsync(new HealthCheckContext(), CancellationToken.None);

        Assert.Equal(HealthStatus.Healthy, result.Status);
    }

    [Theory]
    [InlineData("https://[::]:443", 443, true)]
    [InlineData("https://+:443", 443, true)]
    [InlineData("http://[::]:8080", 443, false)]
    [InlineData("https://[::]:8443", 443, false)]
    public void ParsesKestrelHttpsAddresses(string address, int port, bool expected)
        => Assert.Equal(expected, DnsListenersHealthCheck.IsHttpsOnPort(address, port));

    private static DnsListenersHealthCheck Create(
        IDnsListenerReadiness dns,
        bool tlsEnabled,
        string[]? httpsAddresses = null)
    {
        var tls = new TlsConfiguration { Enabled = tlsEnabled, HttpsPort = 443 };
        var addresses = Substitute.For<IServerAddressesFeature>();
        addresses.Addresses.Returns(httpsAddresses ?? []);
        var features = new FeatureCollection();
        features.Set(addresses);
        var server = Substitute.For<IServer>();
        server.Features.Returns(features);
        return new DnsListenersHealthCheck(dns, Monitor(tls), server);
    }

    private static IOptionsMonitor<T> Monitor<T>(T value)
    {
        var monitor = Substitute.For<IOptionsMonitor<T>>();
        monitor.CurrentValue.Returns(value);
        monitor.Get(Arg.Any<string?>()).Returns(value);
        return monitor;
    }
}
