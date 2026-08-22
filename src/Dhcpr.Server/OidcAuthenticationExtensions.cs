using Dhcpr.Core;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.HttpOverrides;

namespace Dhcpr.Server;

public static class OidcAuthenticationExtensions
{
    public const string DnsViewerPolicy = "DnsViewer";
    public const string DnsAdminPolicy = "DnsAdmin";
    public const string LoginPath = "/account/login";
    public const string LogoutPath = "/account/logout";

    public static WebApplicationBuilder AddDhcprAuthentication(this WebApplicationBuilder builder)
    {
        builder.Services.AddOptions<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme)
            .BindConfiguration("Authentication:Keycloak");
        builder.Services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie()
            .AddOpenIdConnect();
        builder.Services.AddOptions<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme)
            .PostConfigure(static options =>
            {
                // PAR authorize GETs 502 at the proxy before Keycloak sees them; use classic authorize.
                options.PushedAuthorizationBehavior = PushedAuthorizationBehavior.Disable;
            });
        builder.Services.AddAuthorization(options =>
        {
            options.AddPolicy(
                DnsViewerPolicy,
                policy => policy.RequireRole(ApplicationRoles.DnsUser, ApplicationRoles.DnsAdmin));
            options.AddPolicy(
                DnsAdminPolicy,
                policy => policy.RequireRole(ApplicationRoles.DnsAdmin));
        });
        builder.Services.AddCascadingAuthenticationState();
        return builder;
    }

    public static WebApplication UseDhcprForwardedHeaders(this WebApplication app)
    {
        var forwardedHeadersOptions = new ForwardedHeadersOptions
        {
            ForwardedHeaders = ForwardedHeaders.All
        };
        // Ingress pod IPs aren't predictable in k8s — trust the cluster-internal
        // private ranges instead of allowlisting specific hop IPs.
        forwardedHeadersOptions.KnownProxies.Clear();
        foreach (var cidr in new[]
                 {
                     "10.0.0.0/8",
                     "172.16.0.0/12",
                     "192.168.0.0/16",
                     "127.0.0.0/8",
                     "::1/128",
                     "fc00::/7"
                 })
        {
            forwardedHeadersOptions.KnownIPNetworks.Add(System.Net.IPNetwork.Parse(cidr));
        }

        app.UseForwardedHeaders(forwardedHeadersOptions);
        return app;
    }

    public static WebApplication MapDhcprAccountEndpoints(this WebApplication app)
    {
        app.MapGet(LoginPath, (string? returnUrl) =>
                Results.Challenge(
                    new AuthenticationProperties { RedirectUri = returnUrl ?? "/" },
                    [OpenIdConnectDefaults.AuthenticationScheme]))
            .AllowAnonymous();
        app.MapGet(LogoutPath, async context =>
            {
                await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                await context.SignOutAsync(
                    OpenIdConnectDefaults.AuthenticationScheme,
                    new AuthenticationProperties { RedirectUri = "/" });
            })
            .AllowAnonymous();
        return app;
    }
}
