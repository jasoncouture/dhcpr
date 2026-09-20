namespace Dhcpr.Server.Orleans.DnsCookies;

/// <summary>
/// Silo-local copy of the cluster DNS cookie secret.
/// </summary>
internal static class DnsServerCookieSecretSnapshot
{
    private static readonly object Gate = new();
    private static byte[]? _secret;

    public static byte[]? Get()
    {
        lock (Gate)
            return _secret;
    }

    public static void Replace(byte[] secret)
    {
        ArgumentNullException.ThrowIfNull(secret);
        if (secret.Length < 16)
            throw new ArgumentOutOfRangeException(nameof(secret));

        lock (Gate)
            _secret = secret;
    }

    internal static void Clear()
    {
        lock (Gate)
            _secret = null;
    }
}
