using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Dhcpr.Dns.Core;

using Microsoft.Extensions.Options;

namespace Dhcpr.Server;

public static class DohHostIsolationExtensions
{
    public static WebApplication UseDohHostIsolation(this WebApplication app)
    {
        app.Use(static async (context, next) =>
        {
            var dns = context.RequestServices.GetRequiredService<IOptionsMonitor<DnsConfiguration>>().CurrentValue;
            if (!dns.DnsOverHttp.IsolateHost)
            {
                await next.Invoke();
                return;
            }

            var tls = context.RequestServices.GetRequiredService<IOptionsMonitor<TlsConfiguration>>().CurrentValue;
            var certificate = TryLoadCertificate(context, dns, tls);
            if (!DohHostIsolation.ShouldReturnNotFound(
                    context.Request.Path,
                    context.Request.Host,
                    dns,
                    tls,
                    certificate))
            {
                await next.Invoke();
                return;
            }

            context.Response.StatusCode = StatusCodes.Status404NotFound;
        });
        return app;
    }

    private static X509Certificate2? TryLoadCertificate(
        HttpContext context,
        DnsConfiguration dns,
        TlsConfiguration tls)
    {
        if (!tls.Enabled || dns.DesignatedResolvers is { Length: > 0 })
            return null;

        try
        {
            return context.RequestServices.GetRequiredService<ITlsServerCertificateProvider>().GetCertificate();
        }
        catch (Exception exception) when (exception is IOException or CryptographicException)
        {
            return null;
        }
    }
}
