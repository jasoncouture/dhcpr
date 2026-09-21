using System.Net;

using Microsoft.AspNetCore.Http;

namespace Dhcpr.Server.UnitTests;

public class PrivateInfrastructureEndpointMiddlewareTests
{
    [Theory]
    [InlineData("/health")]
    [InlineData("/health/ready")]
    [InlineData("/metrics")]
    [InlineData("/metrics/")]
    public async Task PublicClientGets404OnInfrastructurePaths(string path)
    {
        var (context, called) = await InvokeAsync(path, IPAddress.Parse("203.0.113.10"));

        Assert.Equal(StatusCodes.Status404NotFound, context.Response.StatusCode);
        Assert.False(called());
    }

    [Theory]
    [InlineData("/health", "10.1.2.3")]
    [InlineData("/metrics", "192.168.1.10")]
    [InlineData("/health", "172.16.0.5")]
    [InlineData("/metrics", "fc00::1")]
    [InlineData("/health", "127.0.0.1")]
    [InlineData("/metrics", "::1")]
    [InlineData("/health", "::ffff:10.0.0.8")]
    public async Task PrivateOrLoopbackClientIsPassedThrough(string path, string address)
    {
        var (context, called) = await InvokeAsync(path, IPAddress.Parse(address));

        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
        Assert.True(called());
    }

    [Fact]
    public async Task OtherPathsAreUnchangedForPublicClients()
    {
        var (context, called) = await InvokeAsync("/dns-query", IPAddress.Parse("203.0.113.10"));

        Assert.Equal(StatusCodes.Status200OK, context.Response.StatusCode);
        Assert.True(called());
    }

    [Fact]
    public async Task MissingRemoteAddressIs404OnInfrastructurePaths()
    {
        var (context, called) = await InvokeAsync("/metrics", remote: null);

        Assert.Equal(StatusCodes.Status404NotFound, context.Response.StatusCode);
        Assert.False(called());
    }

    private static async Task<(HttpContext Context, Func<bool> Called)> InvokeAsync(
        string path,
        IPAddress? remote)
    {
        var context = new DefaultHttpContext();
        context.Request.Path = path;
        context.Connection.RemoteIpAddress = remote;
        var called = false;
        var middleware = new PrivateInfrastructureEndpointMiddleware(_ =>
        {
            called = true;
            return Task.CompletedTask;
        });

        await middleware.Invoke(context);
        return (context, () => called);
    }
}
