namespace Dhcpr.Dns.Core.RootZone;

public sealed class NamedRootHttpClient(HttpClient httpClient)
{
    public Task<HttpResponseMessage> GetAsync(string url, CancellationToken cancellationToken)
        => httpClient.GetAsync(url, cancellationToken);
}
