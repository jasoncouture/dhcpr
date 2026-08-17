namespace Dhcpr.Dns.Core.RootZone;

public sealed class RootZoneHttpClient : IRootZoneHttpClient
{
    private readonly HttpClient _httpClient;

    public RootZoneHttpClient(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task<HttpResponseMessage> GetRootZoneAsync(CancellationToken cancellationToken)
        => await _httpClient.GetAsync(
            RootZonePaths.RootZoneUrl,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
}
