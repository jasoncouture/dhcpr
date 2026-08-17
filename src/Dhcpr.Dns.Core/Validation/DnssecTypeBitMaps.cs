using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol;

namespace Dhcpr.Dns.Core.Validation;

/// <summary>
/// RFC 4034 §4.1.2 / RFC 5155 type bit map helpers for NSEC / NSEC3.
/// </summary>
public static class DnssecTypeBitMaps
{
    public static bool Contains(ImmutableArray<byte> typeBitMaps, DomainRecordType type)
    {
        var typeValue = (ushort)type;
        var window = typeValue >> 8;
        var bit = typeValue & 0xFF;

        var i = 0;
        while (i + 2 <= typeBitMaps.Length)
        {
            var blockWindow = typeBitMaps[i];
            var blockLength = typeBitMaps[i + 1];
            i += 2;
            if (blockLength == 0 || i + blockLength > typeBitMaps.Length)
                return false;

            if (blockWindow == window)
            {
                var byteIndex = bit / 8;
                if (byteIndex >= blockLength)
                    return false;
                var mask = (byte)(0x80 >> (bit % 8));
                return (typeBitMaps[i + byteIndex] & mask) != 0;
            }

            i += blockLength;
        }

        return false;
    }

    public static ImmutableArray<byte> FromTypes(params DomainRecordType[] types)
    {
        if (types.Length == 0)
            return ImmutableArray<byte>.Empty;

        var windows = new SortedDictionary<int, byte[]>();
        foreach (var type in types)
        {
            var typeValue = (ushort)type;
            var window = typeValue >> 8;
            var bit = typeValue & 0xFF;
            if (!windows.TryGetValue(window, out var bitmap))
            {
                bitmap = new byte[32];
                windows[window] = bitmap;
            }

            bitmap[bit / 8] |= (byte)(0x80 >> (bit % 8));
        }

        var builder = ImmutableArray.CreateBuilder<byte>();
        foreach (var (window, bitmap) in windows)
        {
            var length = bitmap.Length;
            while (length > 0 && bitmap[length - 1] == 0)
                length--;
            if (length == 0)
                continue;
            builder.Add((byte)window);
            builder.Add((byte)length);
            builder.AddRange(bitmap.AsSpan(0, length).ToArray());
        }

        return builder.ToImmutable();
    }
}
