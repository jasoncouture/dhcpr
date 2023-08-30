using Microsoft.Extensions.Configuration;

namespace Dhcpr.Server;

public static class ConfigurationLoaderExtensions
{
    private static IConfiguration GetConfiguration(string jsonFile, string environmentVariablePrefix)
    {
        var builder = new ConfigurationBuilder();
        builder.AddJsonFile(jsonFile, optional: false, reloadOnChange: true);
        builder.AddEnvironmentVariables(environmentVariablePrefix);
        builder.AddCommandLine(Environment.GetCommandLineArgs());
        return builder.Build();
    }
    
    public static IConfiguration GetDhcpConfiguration(this IConfiguration configuration)
        => GetDhcpConfiguration(configuration.Get<ServerConfiguration>()!);

    public static IConfiguration GetDhcpConfiguration(this ServerConfiguration configuration)
        => GetConfiguration(configuration.DhcpConfigurationFile, "DHCP");

    public static IConfiguration GetDnsConfiguration(this IConfiguration configuration)
        => GetDnsConfiguration(configuration.Get<ServerConfiguration>()!);

    public static IConfiguration GetDnsConfiguration(this ServerConfiguration configuration)
        => GetConfiguration(configuration.DnsConfigurationFile, "DNS");
}