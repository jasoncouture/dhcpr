using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Net;
using System.Security.Cryptography;

namespace Dhcpr.Dns.Core.Protocol;

/// <summary>
/// 16-octet RFC 9018-shaped server cookie: version, timestamp, HMAC-SHA256
/// truncated to 8 octets over client cookie + header + client IP. The HMAC
/// key comes from <see cref="IDnsServerCookieSecretSource"/> so every silo
/// can share one secret.
/// </summary>
public sealed class DnsServerCookieFactory : IDnsServerCookieFactory
{
    public const int ServerCookieLength = 16;
    public const byte Version = 1;
    public static readonly TimeSpan Lifetime = TimeSpan.FromHours(1);
    public static readonly TimeSpan ClockSkew = TimeSpan.FromMinutes(5);

    private readonly IDnsServerCookieSecretSource _secrets;
    private readonly TimeProvider _time;

    public DnsServerCookieFactory(IDnsServerCookieSecretSource secrets, TimeProvider timeProvider)
    {
        _secrets = secrets;
        _time = timeProvider;
    }

    public ImmutableArray<byte> Create(ReadOnlySpan<byte> clientCookie, IPAddress clientAddress)
    {
        if (!TryCreate(clientCookie, clientAddress, out var cookie))
            throw new InvalidOperationException("DNS server cookie secret is not available.");

        return cookie;
    }

    public bool TryCreate(
        ReadOnlySpan<byte> clientCookie,
        IPAddress clientAddress,
        out ImmutableArray<byte> serverCookie)
    {
        serverCookie = default;
        ArgumentOutOfRangeException.ThrowIfNotEqual(clientCookie.Length, EdnsCookie.ClientCookieLength);
        ArgumentNullException.ThrowIfNull(clientAddress);
        if (!_secrets.TryGetSecret(out var secret) || secret.Length < 16)
            return false;

        Span<byte> cookie = stackalloc byte[ServerCookieLength];
        cookie[0] = Version;
        var now = (uint)_time.GetUtcNow().ToUnixTimeSeconds();
        BinaryPrimitives.WriteUInt32BigEndian(cookie[4..8], now);
        WriteHash(secret.Span, clientCookie, cookie[..8], clientAddress, cookie[8..]);
        serverCookie = ImmutableArray.Create(cookie);
        return true;
    }

    public bool IsValid(
        ReadOnlySpan<byte> clientCookie,
        ReadOnlySpan<byte> serverCookie,
        IPAddress clientAddress)
    {
        if (clientCookie.Length != EdnsCookie.ClientCookieLength)
            return false;
        if (serverCookie.Length != ServerCookieLength)
            return false;
        if (serverCookie[0] != Version)
            return false;
        if (clientAddress is null)
            return false;
        if (!_secrets.TryGetSecret(out var secret) || secret.Length < 16)
            return false;

        var timestamp = BinaryPrimitives.ReadUInt32BigEndian(serverCookie[4..8]);
        var now = _time.GetUtcNow().ToUnixTimeSeconds();
        var age = now - timestamp;
        if (age > (long)Lifetime.TotalSeconds || age < -(long)ClockSkew.TotalSeconds)
            return false;

        Span<byte> expected = stackalloc byte[8];
        WriteHash(secret.Span, clientCookie, serverCookie[..8], clientAddress, expected);
        return CryptographicOperations.FixedTimeEquals(expected, serverCookie[8..]);
    }

    private static void WriteHash(
        ReadOnlySpan<byte> secret,
        ReadOnlySpan<byte> clientCookie,
        ReadOnlySpan<byte> header,
        IPAddress clientAddress,
        Span<byte> destination)
    {
        Span<byte> input = stackalloc byte[8 + 8 + 16];
        clientCookie.CopyTo(input);
        header.CopyTo(input[8..]);
        var ipLength = WriteClientAddress(clientAddress, input[16..]);
        Span<byte> hash = stackalloc byte[32];
        HMACSHA256.HashData(secret, input[..(16 + ipLength)], hash);
        hash[..8].CopyTo(destination);
    }

    private static int WriteClientAddress(IPAddress address, Span<byte> destination)
    {
        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();

        if (!address.TryWriteBytes(destination, out var written))
            throw new ArgumentException("Client address could not be written.", nameof(address));

        return written;
    }
}
