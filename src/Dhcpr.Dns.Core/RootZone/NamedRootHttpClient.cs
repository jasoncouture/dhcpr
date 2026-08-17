namespace Dhcpr.Dns.Core.RootZone;

public sealed class NamedRootHttpClient : INamedRootHttpClient
{
    private readonly HttpClient _httpClient;

    public NamedRootHttpClient(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public Task<HttpResponseMessage> GetAsync(string url, CancellationToken cancellationToken)
        => _httpClient.GetAsync(url, cancellationToken);
}
