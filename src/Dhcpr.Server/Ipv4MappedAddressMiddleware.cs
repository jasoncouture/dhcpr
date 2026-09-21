using System.Net;

namespace Dhcpr.Server;

/// <summary>
/// Dual-stack sockets report IPv4 peers as <c>::ffff:a.b.c.d</c>.
/// Rewrite those to IPv4 so DoH, DynDNS, and logs see the real family.
/// </summary>
internal sealed class Ipv4MappedAddressMiddleware(RequestDelegate next)
{
    public async Task Invoke(HttpContext context)
    {
        Unmap(context.Connection);
        await next.Invoke(context);
    }

    internal static void Unmap(ConnectionInfo connection)
    {
        if (connection.RemoteIpAddress is { } remote && remote.IsIPv4MappedToIPv6)
            connection.RemoteIpAddress = remote.MapToIPv4();

        if (connection.LocalIpAddress is { } local && local.IsIPv4MappedToIPv6)
            connection.LocalIpAddress = local.MapToIPv4();
    }
}

public static class Ipv4MappedAddressExtensions
{
    public static IApplicationBuilder UseIpv4MappedAddresses(this IApplicationBuilder app)
        => app.UseMiddleware<Ipv4MappedAddressMiddleware>();
}
