using Dhcpr.Dns.Core.Protocol;

namespace Dhcpr.Server.Orleans.DnsCookies;

/// <summary>
/// Reads the silo-local snapshot filled by
/// <see cref="DnsServerCookieSecretOrleansBridge"/>.
/// </summary>
public sealed class OrleansDnsServerCookieSecretSource : IDnsServerCookieSecretSource
{
    public bool TryGetSecret(out ReadOnlyMemory<byte> secret)
    {
        var current = DnsServerCookieSecretSnapshot.Get();
        if (current is not { Length: >= 16 })
        {
            secret = default;
            return false;
        }

        secret = current;
        return true;
    }
}
