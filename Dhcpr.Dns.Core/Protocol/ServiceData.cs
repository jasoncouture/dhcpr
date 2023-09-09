﻿namespace Dhcpr.Dns.Core.Protocol;

public record ServiceData(ushort Priority, ushort Weight, ushort Port, DomainLabels Name) : IDomainResourceRecordData
{
    public int Size => (sizeof(ushort) * 3) + Name.Size;
    public void WriteTo(ref Span<byte> span)
    {
        DomainMessageEncoder.EncodeAndAdvance(ref span, Priority);
        DomainMessageEncoder.EncodeAndAdvance(ref span, Weight);
        DomainMessageEncoder.EncodeAndAdvance(ref span, Port);
        DomainMessageEncoder.EncodeAndAdvance(ref span, Name);
    }

    public static IDomainResourceRecordData ReadFrom(ReadOnlySpan<byte> bytes)
    {
        var priority = DomainMessageEncoder.ReadUnsignedShortAndAdvance(ref bytes);
        var weight = DomainMessageEncoder.ReadUnsignedShortAndAdvance(ref bytes);
        var port = DomainMessageEncoder.ReadUnsignedShortAndAdvance(ref bytes);
        var name = DomainMessageEncoder.ReadLabelsAndAdvance(ref bytes);
        return new ServiceData(priority, weight, port, name);
    }
}