namespace Dhcpr.Dns.Core.RootZone;

public interface INamedRootHttpClient
{
    /// <summary>
    /// Issues a GET to <paramref name="url"/> (used for named.root / hint files).
    /// </summary>
    Task<HttpResponseMessage> GetAsync(string url, CancellationToken cancellationToken);
}
