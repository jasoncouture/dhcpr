using k8s;

using Orleans.Clustering.Kubernetes;
using Orleans.Configuration;
using Orleans.Dashboard;
using Orleans.Hosting;

namespace Dhcpr.Server;

public static class OrleansServiceCollectionExtensions
{
    public static WebApplicationBuilder AddDhcprOrleans(this WebApplicationBuilder builder)
    {
        builder.UseOrleans(static silo =>
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
            else
            {
                silo.UseLocalhostClustering();
            }

            silo.AddDashboard();
        });

        return builder;
    }
}
