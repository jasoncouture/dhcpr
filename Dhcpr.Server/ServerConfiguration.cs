using Microsoft.Extensions.Configuration;

public sealed class ServerConfiguration
{
    public string DnsConfigurationFile { get; set; } = "dns.json";
    public string DhcpConfigurationFile { get; set; } = "dhcp.json";
}

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