using System.Collections.Immutable;

using Dhcpr.Dns.Core.Protocol.Parser;

namespace Dhcpr.Dns.Core.Protocol.RecordData;

/// <summary>RFC 9460 SVCB / HTTPS RDATA. TargetName is never compressed on the wire.</summary>
public sealed record SvcbData(
    ushort Priority,
    DomainLabels TargetName,
    ImmutableArray<SvcbParameter> Parameters) : IDomainResourceRecordData
{
    public SvcbData(ushort priority, DomainLabels targetName)
        : this(priority, targetName, ImmutableArray<SvcbParameter>.Empty)
    {
    }

    public int EstimatedSize =>
        sizeof(ushort) + TargetName.EstimatedSize + Parameters.Sum(static p => 4 + p.Value.Length);

    public void WriteTo(ref DnsParsingSpan span)
    {
        var origin = span;
        span = span[2..];
        DomainMessageEncoder.EncodeAndAdvance(ref span, Priority);
        DomainMessageEncoder.EncodeUncompressedAndAdvance(ref span, TargetName);
        foreach (var parameter in Parameters.OrderBy(static p => (ushort)p.Key))
        {
            DomainMessageEncoder.EncodeAndAdvance(ref span, (ushort)parameter.Key);
            DomainMessageEncoder.EncodeAndAdvance(ref span, (ushort)parameter.Value.Length);
            parameter.Value.CopyTo(span);
            span = span[parameter.Value.Length..];
        }

        DomainMessageEncoder.EncodeAndAdvance(ref origin, (ushort)(span.Offset - (origin.Offset + 2)));
    }

    public static IDomainResourceRecordData ReadFrom(ref ReadOnlyDnsParsingSpan bytes, int dataLength)
    {
        var start = bytes.Offset;
        var priority = DomainMessageEncoder.ReadUnsignedShortAndAdvance(ref bytes);
        var target = DomainMessageEncoder.ReadLabelsAndAdvance(ref bytes);
        var consumed = bytes.Offset - start;
        if (consumed > dataLength)
            throw new InvalidDataException("SVCB TargetName overruns RDLENGTH.");

        var remaining = dataLength - consumed;
        var parameters = ImmutableArray.CreateBuilder<SvcbParameter>();
        ushort? previousKey = null;
        while (remaining > 0)
        {
            if (remaining < 4)
                throw new InvalidDataException("Truncated SVCB parameter header.");

            var key = DomainMessageEncoder.ReadUnsignedShortAndAdvance(ref bytes);
            var length = DomainMessageEncoder.ReadUnsignedShortAndAdvance(ref bytes);
            remaining -= 4;
            if (remaining < length)
                throw new InvalidDataException("Truncated SVCB parameter value.");
            if (previousKey is { } previous && key <= previous)
                throw new InvalidDataException("SVCB parameters must be in strictly increasing key order.");

            var value = bytes.CurrentSpan[..length].ToImmutableArray();
            bytes = bytes[length..];
            remaining -= length;
            previousKey = key;
            parameters.Add(new SvcbParameter((SvcbParameterKey)key, value));
        }

        return new SvcbData(priority, target, parameters.ToImmutable());
    }
}
