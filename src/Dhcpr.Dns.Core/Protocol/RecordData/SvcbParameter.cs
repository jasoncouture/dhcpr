using System.Collections.Immutable;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

public readonly record struct SvcbParameter(SvcbParameterKey Key, ImmutableArray<byte> Value)
{
    public static SvcbParameter Alpn(params string[] identifiers)
    {
        var size = 0;
        foreach (var id in identifiers)
            size += 1 + Encoding.ASCII.GetByteCount(id);

        var buffer = new byte[size];
        var offset = 0;
        foreach (var id in identifiers)
        {
            var byteCount = Encoding.ASCII.GetByteCount(id);
            if (byteCount is 0 or > 255)
                throw new ArgumentException($"ALPN identifier length must be 1–255 bytes: {id}", nameof(identifiers));
            buffer[offset++] = (byte)byteCount;
            offset += Encoding.ASCII.GetBytes(id, buffer.AsSpan(offset));
        }

        return new SvcbParameter(SvcbParameterKey.Alpn, buffer.ToImmutableArray());
    }

    public static SvcbParameter Port(ushort port)
    {
        var buffer = new byte[2];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(buffer, port);
        return new SvcbParameter(SvcbParameterKey.Port, buffer.ToImmutableArray());
    }

    public static SvcbParameter Ipv4Hint(params IPAddress[] addresses)
        => AddressHint(SvcbParameterKey.Ipv4Hint, AddressFamily.InterNetwork, 4, addresses);

    public static SvcbParameter Ipv6Hint(params IPAddress[] addresses)
        => AddressHint(SvcbParameterKey.Ipv6Hint, AddressFamily.InterNetworkV6, 16, addresses);

    public static SvcbParameter DohPath(string path)
        => new(SvcbParameterKey.DohPath, Encoding.UTF8.GetBytes(path).ToImmutableArray());

    private static SvcbParameter AddressHint(
        SvcbParameterKey key,
        AddressFamily family,
        int addressSize,
        IPAddress[] addresses)
    {
        var buffer = new byte[addresses.Length * addressSize];
        var offset = 0;
        foreach (var address in addresses)
        {
            if (address.AddressFamily != family)
                throw new ArgumentException($"Expected {family} address, got {address}.", nameof(addresses));
            if (!address.TryWriteBytes(buffer.AsSpan(offset), out var written) || written != addressSize)
                throw new ArgumentException($"Could not write {address}.", nameof(addresses));
            offset += addressSize;
        }

        return new SvcbParameter(key, buffer.ToImmutableArray());
    }
}
