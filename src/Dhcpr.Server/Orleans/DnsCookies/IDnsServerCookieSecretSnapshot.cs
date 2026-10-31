namespace Dhcpr.Server.Orleans.DnsCookies;

/// <summary>
/// Silo-local copy of the cluster DNS cookie secret.
/// </summary>
public interface IDnsServerCookieSecretSnapshot
{
    byte[]? Get();

    void Replace(byte[] secret);
}
