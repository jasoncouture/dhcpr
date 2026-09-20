namespace Dhcpr.Dns.Core.Protocol;

/// <summary>
/// HMAC key for RFC 9018 server cookies. Cluster hosts share one key;
/// a process-local source is only the fallback when Orleans is not wired.
/// </summary>
public interface IDnsServerCookieSecretSource
{
    bool TryGetSecret(out ReadOnlyMemory<byte> secret);
}
