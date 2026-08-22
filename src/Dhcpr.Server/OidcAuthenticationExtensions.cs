using System.IdentityModel.Tokens.Jwt;

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
            .PostConfigure<ILoggerFactory>((options, loggerFactory) =>
            {
                // PAR authorize GETs 502 at the proxy before Keycloak sees them; use classic authorize.
                options.PushedAuthorizationBehavior = PushedAuthorizationBehavior.Disable;

                // TEMP: dump tokens so we can inspect groups. Remove after debugging.
                var logger = loggerFactory.CreateLogger("Dhcpr.Server.OpenIdConnect");
                var prior = options.Events.OnTokenValidated;
                options.Events.OnTokenValidated = async context =>
                {
                    if (prior is not null)
                        await prior(context);

                    var idToken = context.TokenEndpointResponse?.IdToken;
                    if (string.IsNullOrEmpty(idToken) && context.SecurityToken is JwtSecurityToken jwt)
                        idToken = jwt.RawData;

                    logger.LogWarning(
                        "TEMP OIDC jwt id_token={IdToken} access_token={AccessToken}",
                        idToken,
                        context.TokenEndpointResponse?.AccessToken);
                };
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
