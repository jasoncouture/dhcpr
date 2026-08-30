using Dhcpr.Dns.Core;

namespace Dhcpr.Server;

public static class KestrelTlsExtensions
{
    public static WebApplicationBuilder UseTlsCertificateForHttps(this WebApplicationBuilder builder)
    {
        builder.WebHost.ConfigureKestrel(static (context, options) =>
        {
            var tls = context.Configuration.GetSection("TLS").Get<TlsConfiguration>() ?? new TlsConfiguration();
            if (!tls.Enabled)
                return;

            options.ConfigureHttpsDefaults(https =>
            {
                https.ServerCertificateSelector = (_, _) =>
                    options.ApplicationServices
                        .GetRequiredService<ITlsServerCertificateProvider>()
                        .GetCertificate();
            });
        });
        return builder;
    }
}
