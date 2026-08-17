namespace Dhcpr.Dns.Core.RootZone;

public interface IRootZoneHttpClient
{
    /// <summary>
    /// Downloads the IANA root zone file.
    /// </summary>
    Task<HttpResponseMessage> GetRootZoneAsync(CancellationToken cancellationToken);
}
