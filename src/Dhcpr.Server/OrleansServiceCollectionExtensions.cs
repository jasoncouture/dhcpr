using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

using k8s;

using Microsoft.Extensions.Options;

using Orleans.Clustering.Kubernetes;
using Orleans.Configuration;
using Orleans.Dashboard;
using Orleans.Hosting;

namespace Dhcpr.Server;

public static class OrleansServiceCollectionExtensions
{
    public static WebApplicationBuilder AddDhcprOrleans(this WebApplicationBuilder builder)
    {
        builder.Services.AddSingleton<IValidateOptions<OrleansConfiguration>, OrleansConfigurationValidator>();
        builder.Services.AddOptionsWithValidateOnStart<OrleansConfiguration>()
            .BindConfiguration("Orleans");

        builder.UseOrleans(silo =>
        {
            silo.Configure<ClusterOptions>(static options =>
            {
                options.ClusterId = "dhcpr";
                options.ServiceId = "dhcpr";
            });

            // Prefer the Kubernetes client's in-cluster probe — do not invent an env-var flag.
            if (KubernetesClientConfiguration.IsInCluster())
            {
                silo.UseKubernetesHosting();
                silo.UseKubeMembership();
            }
            else if (builder.Configuration.GetValue<bool>("Orleans:UseConsul"))
            {
                var orleans = builder.Configuration.GetSection("Orleans").Get<OrleansConfiguration>()
                    ?? new OrleansConfiguration();
                if (!orleans.TryValidate(out var error))
                    throw new InvalidOperationException(error);

                silo.UseConsulSiloClustering(options =>
                {
                    var token = string.IsNullOrWhiteSpace(orleans.Consul.Token)
                        ? null
                        : orleans.Consul.Token;
                    options.ConfigureConsulClient(new Uri(orleans.Consul.Address), token);
                    if (!string.IsNullOrWhiteSpace(orleans.Consul.KvRootFolder))
                        options.KvRootFolder = orleans.Consul.KvRootFolder;
                });
                silo.ConfigureEndpoints(
                    ResolveAdvertisedIP(orleans),
                    siloPort: orleans.SiloPort,
                    gatewayPort: orleans.GatewayPort,
                    listenOnAnyHostAddress: true);
            }
            else
            {
#if DEBUG
                silo.UseLocalhostClustering();
#else
                throw new InvalidOperationException("No clustering configuration is set, unable to start.");
#endif
            }

            silo.AddDashboard();
        });

        return builder;
    }

    private static IPAddress ResolveAdvertisedIP(OrleansConfiguration orleans)
    {
        if (IPAddress.TryParse(orleans.AdvertisedIP, out var configured))
            return configured;

        IPAddress? v6 = null;
        foreach (var network in NetworkInterface.GetAllNetworkInterfaces())
        {
            if (network.OperationalStatus is not OperationalStatus.Up)
                continue;
            if (network.NetworkInterfaceType is NetworkInterfaceType.Loopback)
                continue;

            foreach (var unicast in network.GetIPProperties().UnicastAddresses)
            {
                var address = unicast.Address;
                if (IPAddress.IsLoopback(address) || address.IsIPv6LinkLocal)
                    continue;
                if (address.AddressFamily is AddressFamily.InterNetwork)
                    return address;
                v6 ??= address;
            }
        }

        if (v6 is not null)
            return v6;

        throw new InvalidOperationException(
            "Orleans:AdvertisedIP must be set when no non-loopback address is available");
    }
}
