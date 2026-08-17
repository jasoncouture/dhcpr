namespace Dhcpr.Dns.Core.RootZone;

public interface INamedRootHttpClient
{
    Task<HttpResponseMessage> GetAsync(string url, CancellationToken cancellationToken);
}
