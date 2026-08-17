namespace Dhcpr.Dns.Core.RootZone;

public sealed class RootZoneHttpClient : IRootZoneHttpClient
{
    private readonly IHttpClientFactory _httpClientFactory;

    public RootZoneHttpClient(IHttpClientFactory httpClientFactory)
    {
        _httpClientFactory = httpClientFactory;
    }

    public async Task<HttpResponseMessage> GetRootZoneAsync(CancellationToken cancellationToken)
        => await _httpClientFactory.CreateClient(nameof(RootZoneHttpClient)).GetAsync(
            RootZonePaths.RootZoneUrl,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
}
