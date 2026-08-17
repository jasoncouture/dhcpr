namespace Dhcpr.Dns.Core.RootZone;

public sealed class NamedRootHttpClient : INamedRootHttpClient
{
    private readonly IHttpClientFactory _httpClientFactory;

    public NamedRootHttpClient(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    public async Task<HttpResponseMessage> GetAsync(string url, CancellationToken cancellationToken)
        => await _httpClientFactory.CreateClient(nameof(NamedRootHttpClient)).GetAsync(url, cancellationToken);
}
