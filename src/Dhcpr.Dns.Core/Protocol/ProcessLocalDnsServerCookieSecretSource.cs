using System.Security.Cryptography;

namespace Dhcpr.Dns.Core.Protocol;

/// <summary>
/// One-shot random key for a single process. Replaced in the server
/// host by the Orleans-backed source so silos share a cookie secret.
/// </summary>
public sealed class ProcessLocalDnsServerCookieSecretSource : IDnsServerCookieSecretSource
{
    private readonly byte[] _secret = new byte[32];

    public ProcessLocalDnsServerCookieSecretSource()
        => RandomNumberGenerator.Fill(_secret);

    public bool TryGetSecret(out ReadOnlyMemory<byte> secret)
    {
        secret = _secret;
        return true;
    }
}
