using System.Buffers;
using System.Security.Cryptography;

using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Validation;

/// <summary>DS digest over the canonical owner name and DNSKEY RDATA (RFC 4034 §5.1.4).</summary>
public static class TrustAnchorDigest
{
    public static string Sha256(DomainResourceRecord dnsKeyRecord)
    {
        var size = dnsKeyRecord.EstimatedSize;
        var buffer = ArrayPool<byte>.Shared.Rent(size * 2);
        try
        {
            var span = buffer.AsSpan();
            DomainResourceRecordCanonicalizationExtensions.EncodeCanonicalName(ref span, dnsKeyRecord.Name);
            var offset = buffer.Length - span.Length;

            using (var dict = DictionaryPool<string, int>.Default.Get())
            {
                var parsingSpan = new DnsParsingSpan(dict, buffer.AsSpan(offset));
                dnsKeyRecord.Data.WriteTo(ref parsingSpan);
                var rdataLength = parsingSpan.Offset - 2;
                buffer.AsSpan(offset + 2, rdataLength).CopyTo(buffer.AsSpan(offset));
                offset += rdataLength;
            }

            return Convert.ToHexString(SHA256.HashData(buffer.AsSpan(0, offset)));
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }
}
