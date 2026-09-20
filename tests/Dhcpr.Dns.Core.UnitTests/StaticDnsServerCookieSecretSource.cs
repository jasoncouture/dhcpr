using Dhcpr.Dns.Core.Protocol;

namespace Dhcpr.Dns.Core.UnitTests;

internal sealed class StaticDnsServerCookieSecretSource : IDnsServerCookieSecretSource
{
    private readonly byte[] _secret;

    public StaticDnsServerCookieSecretSource(ReadOnlyMemory<byte> secret)
    {
        if (secret.Length < 16)
            throw new ArgumentOutOfRangeException(nameof(secret));

        _secret = secret.ToArray();
    }

    public bool TryGetSecret(out ReadOnlyMemory<byte> secret)
    {
        secret = _secret;
        return true;
    }
}

internal sealed class EmptyDnsServerCookieSecretSource : IDnsServerCookieSecretSource
{
    public bool TryGetSecret(out ReadOnlyMemory<byte> secret)
    {
        secret = default;
        return false;
    }
}
