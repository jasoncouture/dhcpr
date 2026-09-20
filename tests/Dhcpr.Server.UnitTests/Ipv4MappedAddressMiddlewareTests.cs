using System.Net;

using Microsoft.AspNetCore.Http;

namespace Dhcpr.Server.UnitTests;

public class Ipv4MappedAddressMiddlewareTests
{
    [Fact]
    public async Task UnmapsClientAndServerIpv4MappedAddresses()
    {
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = IPAddress.Parse("::ffff:203.0.113.10");
        context.Connection.LocalIpAddress = IPAddress.Parse("::ffff:127.0.0.1");
        var called = false;
        var middleware = new Ipv4MappedAddressMiddleware(_ =>
        {
            called = true;
            return Task.CompletedTask;
        });

        await middleware.Invoke(context);

        Assert.Equal(IPAddress.Parse("203.0.113.10"), context.Connection.RemoteIpAddress);
        Assert.Equal(IPAddress.Parse("127.0.0.1"), context.Connection.LocalIpAddress);
        Assert.True(called);
    }

    [Fact]
    public async Task LeavesNativeIpv6AndNullAlone()
    {
        var v6 = IPAddress.Parse("2001:db8::1");
        var context = new DefaultHttpContext();
        context.Connection.RemoteIpAddress = v6;
        context.Connection.LocalIpAddress = null;
        var middleware = new Ipv4MappedAddressMiddleware(_ => Task.CompletedTask);

        await middleware.Invoke(context);

        Assert.Equal(v6, context.Connection.RemoteIpAddress);
        Assert.Null(context.Connection.LocalIpAddress);
    }
}
