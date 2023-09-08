using Dhcpr.Data.Abstractions;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Dhcpr.Data.Dns.Models;

public class InterNetworkVersion4AddressResourceRecord : DnsResourceRecord,
    IDataRecord<InterNetworkVersion4AddressResourceRecord>
{
    public byte[] InterNetworkVersion4Address { get; set; } = Array.Empty<byte>();

    public override ResourceRecordType RecordType
    {
        get => ResourceRecordType.A;
        set { }
    }

    static void ISelfBuildingModel<InterNetworkVersion4AddressResourceRecord>.OnModelCreating(
        EntityTypeBuilder<InterNetworkVersion4AddressResourceRecord> entityBuilder)
    {
        entityBuilder
            .Property(i => i.InterNetworkVersion4Address)
            .HasMaxLength(4)
            .IsFixedLength()
            .IsRequired();
    }
}