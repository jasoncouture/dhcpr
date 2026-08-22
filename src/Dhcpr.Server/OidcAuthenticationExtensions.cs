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
    public const string AccessDeniedPath = "/Account/AccessDenied";

    public static WebApplicationBuilder AddDhcprAuthentication(this WebApplicationBuilder builder)
    {
        builder.Services.AddOptions<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme)
            .BindConfiguration("Authentication:Keycloak");
        builder.Services.AddAuthentication(options =>
            {
                options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie(static options =>
            {
                options.LoginPath = LoginPath;
                options.AccessDeniedPath = AccessDeniedPath;
            })
            .AddOpenIdConnect();
        builder.Services.AddOptions<OpenIdConnectOptions>(OpenIdConnectDefaults.AuthenticationScheme)
            .PostConfigure(static options =>
            {
                // PAR authorize GETs 502 at the proxy before Keycloak sees them; use classic authorize.
                options.PushedAuthorizationBehavior = PushedAuthorizationBehavior.Disable;
                options.SignOutScheme = CookieAuthenticationDefaults.AuthenticationScheme;
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
        app.MapGet(LogoutPath, async Task<IResult> (HttpContext context) =>
            {
                // Keycloak requires id_token_hint. That token lives on the cookie ticket;
                // sign out OIDC first so the handler can still read it. A second hit
                // (Blazor) has no ticket — skip the IdP and just go home.
                var idToken = await context.GetTokenAsync(
                    CookieAuthenticationDefaults.AuthenticationScheme,
                    "id_token");
                if (string.IsNullOrEmpty(idToken))
                {
                    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    return Results.Redirect("/");
                }

                return Results.SignOut(
                    new AuthenticationProperties { RedirectUri = "/" },
                    [
                        OpenIdConnectDefaults.AuthenticationScheme,
                        CookieAuthenticationDefaults.AuthenticationScheme
                    ]);
            })
            .AllowAnonymous();
        return app;
    }
}
