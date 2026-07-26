namespace Dhcpr.Dns.Core.RootZone;

public sealed class RootZoneHttpClient(HttpClient httpClient)
{
    public Task<HttpResponseMessage> GetRootZoneAsync(CancellationToken cancellationToken)
        => httpClient.GetAsync(
            RootZonePaths.RootZoneUrl,
            HttpCompletionOption.ResponseHeadersRead,
            cancellationToken);
}
