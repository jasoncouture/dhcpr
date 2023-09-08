using Dhcpr.Data.Abstractions;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Dhcpr.Data.Dns.Models;

public class InterNetworkVersion6AddressDnsResourceRecord : DnsResourceRecord,
    IDataRecord<InterNetworkVersion6AddressDnsResourceRecord>
{
    public byte[] InterNetworkVersion6Address { get; set; } = Array.Empty<byte>();

    public override ResourceRecordType RecordType
    {
        get => ResourceRecordType.AAAA;
        set { }
    }

    static void ISelfBuildingModel<InterNetworkVersion6AddressDnsResourceRecord>.OnModelCreating(
        EntityTypeBuilder<InterNetworkVersion6AddressDnsResourceRecord> entityBuilder)
    {
        entityBuilder
            .Property(i => i.InterNetworkVersion6Address)
            .HasMaxLength(16)
            .IsFixedLength()
            .IsRequired();
    }
}