namespace Dhcpr.Dns.Core.RootZone;

public sealed class NamedRootHttpClient
{
    private readonly HttpClient _httpClient;

    public NamedRootHttpClient(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task<HttpResponseMessage> GetAsync(string url, CancellationToken cancellationToken)
        => await _httpClient.GetAsync(url, cancellationToken);
}
