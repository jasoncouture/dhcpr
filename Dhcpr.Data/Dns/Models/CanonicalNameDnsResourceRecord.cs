using Dhcpr.Data.Abstractions;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Dhcpr.Data.Dns.Models;

public sealed class CanonicalNameDnsResourceRecord : DnsResourceRecord, ISelfBuildingModel<CanonicalNameDnsResourceRecord>
{
    public string Name { get; set; } = string.Empty;

    public override ResourceRecordType RecordType
    {
        get => ResourceRecordType.CNAME;
        set { }
    }

    static void ISelfBuildingModel<CanonicalNameDnsResourceRecord>.OnModelCreating(
        EntityTypeBuilder<CanonicalNameDnsResourceRecord> builder)
    {
        builder.Property(nameof(Name)).HasMaxLength(255).IsRequired().HasColumnName(nameof(Name));
        builder.HasBaseType<DnsResourceRecord>();
    }
}