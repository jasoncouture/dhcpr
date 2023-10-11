namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Files;

public class BindFileConfiguration
{
    public required string[] Paths { get; init; }
    public string? BasePath { get; init; }
}