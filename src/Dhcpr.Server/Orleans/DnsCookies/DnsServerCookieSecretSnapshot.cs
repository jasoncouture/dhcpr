namespace Dhcpr.Server.Orleans.DnsCookies;

/// <inheritdoc cref="IDnsServerCookieSecretSnapshot"/>
public sealed class DnsServerCookieSecretSnapshot : IDnsServerCookieSecretSnapshot
{
    private readonly object _gate = new();
    private byte[]? _secret;

    public byte[]? Get()
    {
        lock (_gate)
            return _secret;
    }

    public void Replace(byte[] secret)
    {
        ArgumentNullException.ThrowIfNull(secret);
        if (secret.Length < 16)
            throw new ArgumentOutOfRangeException(nameof(secret));

        lock (_gate)
            _secret = secret;
    }
}
