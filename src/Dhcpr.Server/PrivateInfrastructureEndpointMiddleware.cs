using System.Net;

using Dhcpr.Core;

namespace Dhcpr.Server;

/// <summary>
/// <c>/health</c> and <c>/metrics</c> are cluster-internal. Public clients
/// get 404. Loopback is allowed — <see cref="IPAddress.IsPrivateAddress"/>
/// does not treat 127.0.0.0/8 or ::1 as private.
/// </summary>
internal sealed class PrivateInfrastructureEndpointMiddleware(RequestDelegate next)
{
    public async Task Invoke(HttpContext context)
    {
        if (IsInfrastructurePath(context.Request.Path) &&
            !IsAllowed(context.Connection.RemoteIpAddress))
        {
            context.Response.StatusCode = StatusCodes.Status404NotFound;
            return;
        }

        await next.Invoke(context);
    }

    internal static bool IsInfrastructurePath(PathString path)
        => path.StartsWithSegments(HealthCheckEndpointExtensions.HealthPath) ||
           path.StartsWithSegments("/metrics");

    internal static bool IsAllowed(IPAddress? address)
        => address is not null &&
           (IPAddress.IsLoopback(address) || address.IsPrivateAddress());
}

public static class PrivateInfrastructureEndpointExtensions
{
    public static IApplicationBuilder UsePrivateInfrastructureEndpoints(this IApplicationBuilder app)
        => app.UseMiddleware<PrivateInfrastructureEndpointMiddleware>();
}
