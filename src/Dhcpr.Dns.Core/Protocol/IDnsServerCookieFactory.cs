using System.Collections.Immutable;
using System.Net;

namespace Dhcpr.Dns.Core.Protocol;

/// <summary>
/// RFC 7873 / 9018 server cookies. Optional: clients that never send a
/// COOKIE still get a normal answer.
/// </summary>
public interface IDnsServerCookieFactory
{
    ImmutableArray<byte> Create(ReadOnlySpan<byte> clientCookie, IPAddress clientAddress);

    bool TryCreate(
        ReadOnlySpan<byte> clientCookie,
        IPAddress clientAddress,
        out ImmutableArray<byte> serverCookie);

    bool IsValid(
        ReadOnlySpan<byte> clientCookie,
        ReadOnlySpan<byte> serverCookie,
        IPAddress clientAddress);
}
