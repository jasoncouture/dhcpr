using System.Security.Cryptography.X509Certificates;

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
                var context = options.ApplicationServices
                    .GetRequiredService<ITlsServerCertificateProvider>()
                    .GetServerCertificateContext();
                https.ServerCertificate = context.TargetCertificate;
                var chain = new X509Certificate2Collection();
                foreach (var certificate in context.IntermediateCertificates)
                    chain.Add(certificate);
                https.ServerCertificateChain = chain;
            });
        });
        return builder;
    }
}
