namespace Dhcpr.Dns.Core.RootZone;

public interface IRootZoneHttpClient
{
    Task<HttpResponseMessage> GetRootZoneAsync(CancellationToken cancellationToken);
}
