using Dhcpr.Dns.Core;
using Dhcpr.Dns.Core.Authoritative;
using Dhcpr.Dns.Core.DynamicDns;

using Microsoft.Extensions.Options;

namespace Dhcpr.Server;

public static class DynDnsEndpointExtensions
{
    public const string NicUpdatePath = "/nic/update";
    public const string V3UpdatePath = "/v3/update";

    public static WebApplication MapDynDnsUpdate(this WebApplication app)
    {
        app.MapGet(NicUpdatePath, HandleUpdateAsync);
        app.MapGet(V3UpdatePath, HandleUpdateAsync);
        return app;
    }

    private static IResult HandleUpdateAsync(
        HttpContext httpContext,
        IDynamicDnsStore store,
        IAuthoritativeZoneStore zones,
        IOptions<DynamicDnsConfiguration> options)
    {
        var config = options.Value;
        var hostnameParam = httpContext.Request.Query["hostname"].ToString();
        var myipParam = httpContext.Request.Query["myip"].ToString();
        var auth = httpContext.Request.Headers.Authorization.ToString();

        string? forwardedFirst = null;
        if (config.TrustForwardedFor)
        {
            var forwarded = httpContext.Request.Headers["X-Forwarded-For"].FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(forwarded))
            {
                forwardedFirst = forwarded
                    .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                    .FirstOrDefault();
            }
        }

        var body = DynDnsUpdateProcessor.Process(
            store,
            zones,
            config,
            auth,
            hostnameParam,
            myipParam,
            httpContext.Connection.RemoteIpAddress,
            forwardedFirst);

        return TextResult(body);
    }

    private static IResult TextResult(string body)
        => Results.Text(body.EndsWith('\n') ? body : $"{body}\n", "text/plain; charset=utf-8");
}
