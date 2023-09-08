using Dhcpr.Data.Abstractions;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Dhcpr.Data.Dns.Models;

public sealed class NameServerDnsResourceRecord : DnsResourceRecord, ISelfBuildingModel<NameServerDnsResourceRecord>
{
    public string Name { get; set; } = string.Empty;

    public override ResourceRecordType RecordType
    {
        get => ResourceRecordType.NS;
        set { }
    }

    static void ISelfBuildingModel<NameServerDnsResourceRecord>.OnModelCreating(
        EntityTypeBuilder<NameServerDnsResourceRecord> builder)
    {
        builder.Property(nameof(Name)).HasMaxLength(255).IsRequired().HasColumnName(nameof(Name));
        builder.HasBaseType<DnsResourceRecord>();
    }
}