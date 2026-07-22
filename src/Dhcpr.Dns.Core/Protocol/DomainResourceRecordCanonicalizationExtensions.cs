using System;
using System.Buffers;
using System.Buffers.Binary;
using System.Collections.Immutable;
using System.Text;
using Dhcpr.Core;
using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Protocol.Parser;
using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Protocol;

public static class DomainResourceRecordCanonicalizationExtensions
{
    /// <summary>
    /// Computes the canonical wire format of a resource record according to RFC 4034 Section 6.2.
    /// This canonical format is used for DNSSEC signature verification.
    /// </summary>
    public static byte[] ToCanonicalWireFormat(this DomainResourceRecord record, uint originalTtl)
    {
        var size = record.EstimatedSize;
        var buffer = ArrayPool<byte>.Shared.Rent(size * 2); // Rent a bit more just in case compression was expanding it.
        try
        {
            var span = buffer.AsSpan();
            var start = span;

            // 1. Owner name (fully expanded, lowercase)
            EncodeCanonicalName(ref span, record.Name);

            // 2. Type
            BinaryPrimitives.WriteUInt16BigEndian(span, (ushort)record.Type);
            span = span[2..];

            // 3. Class
            BinaryPrimitives.WriteUInt16BigEndian(span, (ushort)record.Class);
            span = span[2..];

            // 4. TTL (Original TTL from RRSIG)
            BinaryPrimitives.WriteUInt32BigEndian(span, originalTtl);
            span = span[4..];

            // 5. RDLENGTH & RDATA
            // We need to encode the RDATA into a temporary buffer to know its exact canonical length
            var rdataBuffer = ArrayPool<byte>.Shared.Rent(size);
            int rdataLength;
            try
            {
                var rdataSpan = rdataBuffer.AsSpan();
                rdataLength = EncodeCanonicalRData(rdataSpan, record.Type, record.Data);
                
                BinaryPrimitives.WriteUInt16BigEndian(span, (ushort)rdataLength);
                span = span[2..];

                rdataBuffer.AsSpan(0, rdataLength).CopyTo(span);
                span = span[rdataLength..];
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(rdataBuffer);
            }

            var totalWritten = start.Length - span.Length;
            return start[..totalWritten].ToArray();
        }
        finally
        {
            ArrayPool<byte>.Shared.Return(buffer);
        }
    }

    private static int EncodeCanonicalRData(Span<byte> span, DomainRecordType type, IDomainResourceRecordData data)
    {
        var start = span;
        
        switch (data)
        {
            case NameData nameData when RequiresLowercaseRData(type):
                EncodeCanonicalName(ref span, nameData.Name);
                break;
                
            case StartOfAuthorityData soaData:
                EncodeCanonicalName(ref span, soaData.MasterName);
                EncodeCanonicalName(ref span, soaData.ResponsibleName);
                BinaryPrimitives.WriteInt32BigEndian(span, soaData.SerialNumber);
                span = span[4..];
                BinaryPrimitives.WriteInt32BigEndian(span, (int)soaData.RefreshInterval.TotalSeconds);
                span = span[4..];
                BinaryPrimitives.WriteInt32BigEndian(span, (int)soaData.RetryInterval.TotalSeconds);
                span = span[4..];
                BinaryPrimitives.WriteInt32BigEndian(span, (int)soaData.ExpireInterval.TotalSeconds);
                span = span[4..];
                BinaryPrimitives.WriteInt32BigEndian(span, (int)soaData.MinimumTimeToLive.TotalSeconds);
                span = span[4..];
                break;
                
            case NextSecureData nsecData:
                EncodeCanonicalName(ref span, nsecData.NextDomainName);
                nsecData.TypeBitMaps.CopyTo(span);
                span = span[nsecData.TypeBitMaps.Length..];
                break;

            case ResourceRecordSignatureData rrsigData:
                BinaryPrimitives.WriteUInt16BigEndian(span, (ushort)rrsigData.TypeCovered);
                span = span[2..];
                span[0] = rrsigData.Algorithm;
                span = span[1..];
                span[0] = rrsigData.Labels;
                span = span[1..];
                BinaryPrimitives.WriteUInt32BigEndian(span, rrsigData.OriginalTtl);
                span = span[4..];
                BinaryPrimitives.WriteUInt32BigEndian(span, rrsigData.SignatureExpiration);
                span = span[4..];
                BinaryPrimitives.WriteUInt32BigEndian(span, rrsigData.SignatureInception);
                span = span[4..];
                BinaryPrimitives.WriteUInt16BigEndian(span, rrsigData.KeyTag);
                span = span[2..];
                EncodeCanonicalName(ref span, rrsigData.SignersName);
                rrsigData.Signature.CopyTo(span);
                span = span[rrsigData.Signature.Length..];
                break;

            default:
                // For DNSKEY, DS, NSEC3, TXT, A, AAAA, etc. the wire format is identical to canonical.
                // We can use a temporary DnsParsingSpan just to let it write its own RDATA without compression.
                using (var dict = DictionaryPool<string, int>.Default.Get())
                {
                    // Provide enough size for it to write RDLENGTH and RDATA
                    var tempSpan = new DnsParsingSpan(dict, span);
                    data.WriteTo(ref tempSpan);
                    
                    // data.WriteTo writes RDLENGTH + RDATA. We only want the RDATA here,
                    // so we strip the first 2 bytes (the length).
                    var totalWritten = tempSpan.Offset;
                    span.Slice(2, totalWritten - 2).CopyTo(span);
                    span = span[(totalWritten - 2)..];
                }
                break;
        }

        return start.Length - span.Length;
    }

    private static bool RequiresLowercaseRData(DomainRecordType type)
    {
        return type is DomainRecordType.NS or DomainRecordType.CNAME or DomainRecordType.PTR or DomainRecordType.MX;
    }

    public static void EncodeCanonicalName(ref Span<byte> span, DomainLabels labels)
    {
        foreach (var label in labels.Labels)
        {
            span[0] = (byte)label.Label.Length;
            span = span[1..];
            
            // Lowercase ASCII
            for (var i = 0; i < label.Label.Length; i++)
            {
                span[i] = (byte)char.ToLowerInvariant(label.Label[i]);
            }
            span = span[label.Label.Length..];
        }
        span[0] = 0; // root label
        span = span[1..];
    }
}