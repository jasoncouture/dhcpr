using Dhcpr.Data.Abstractions;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Dhcpr.Data.Dns.Models;

public sealed class PointerDnsResourceRecord : DnsResourceRecord, ISelfBuildingModel<PointerDnsResourceRecord>
{
    public string Name { get; set; } = string.Empty;

    public override ResourceRecordType RecordType
    {
        get => ResourceRecordType.PTR;
        set { }
    }

    static void ISelfBuildingModel<PointerDnsResourceRecord>.OnModelCreating(
        EntityTypeBuilder<PointerDnsResourceRecord> builder)
    {
        builder.Property(nameof(Name)).HasMaxLength(255).IsRequired().HasColumnName(nameof(Name));
        builder.HasBaseType<DnsResourceRecord>();
    }
}