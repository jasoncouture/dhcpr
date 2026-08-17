namespace Dhcpr.Dns.Core.Validation;

/// <summary>
/// RFC 4648 Base32hex (extended hex) used for NSEC3 owner labels.
/// Alphabet: 0-9A-V, no padding in DNS owner names.
/// </summary>
public static class DnssecBase32Hex
{
    private static readonly sbyte[] _decodeMap = CreateDecodeMap();

    private static sbyte[] CreateDecodeMap()
    {
        var map = new sbyte[128];
        Array.Fill(map, (sbyte)-1);
        for (var i = 0; i < 10; i++)
            map['0' + i] = (sbyte)i;
        for (var i = 0; i < 22; i++)
        {
            map['A' + i] = (sbyte)(10 + i);
            map['a' + i] = (sbyte)(10 + i);
        }

        return map;
    }

    public static bool TryDecode(ReadOnlySpan<char> input, Span<byte> output, out int bytesWritten)
    {
        bytesWritten = 0;
        if (input.IsEmpty)
            return true;

        var buffer = 0;
        var bitsLeft = 0;
        foreach (var ch in input)
        {
            if (ch >= _decodeMap.Length || _decodeMap[ch] < 0)
                return false;

            buffer = (buffer << 5) | (byte)_decodeMap[ch];
            bitsLeft += 5;
            if (bitsLeft < 8)
                continue;

            bitsLeft -= 8;
            if (bytesWritten >= output.Length)
                return false;
            output[bytesWritten++] = (byte)((buffer >> bitsLeft) & 0xFF);
        }

        return true;
    }

    public static string Encode(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
            return string.Empty;

        const string alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUV";
        var outputLength = (data.Length * 8 + 4) / 5;
        return string.Create(outputLength, data.ToArray(), static (span, bytes) =>
        {
            var buffer = 0;
            var bitsLeft = 0;
            var outIndex = 0;
            foreach (var b in bytes)
            {
                buffer = (buffer << 8) | b;
                bitsLeft += 8;
                while (bitsLeft >= 5)
                {
                    bitsLeft -= 5;
                    span[outIndex++] = alphabet[(buffer >> bitsLeft) & 0x1F];
                }
            }

            if (bitsLeft > 0)
                span[outIndex] = alphabet[(buffer << (5 - bitsLeft)) & 0x1F];
        });
    }
}
