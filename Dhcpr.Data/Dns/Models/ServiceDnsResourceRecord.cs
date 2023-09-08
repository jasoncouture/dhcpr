using Dhcpr.Data.Abstractions;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Dhcpr.Data.Dns.Models;

public class ServiceDnsResourceRecord : DnsResourceRecord, ISelfBuildingModel<ServiceDnsResourceRecord>
{
    public ushort Priority { get; set; }
    public ushort Weight { get; set; }
    public ushort Port { get; set; }
    public string Name { get; set; } = string.Empty;

    public override ResourceRecordType RecordType
    {
        get => ResourceRecordType.SRV;
        set { }
    }

    static void ISelfBuildingModel<ServiceDnsResourceRecord>.OnModelCreating(
        EntityTypeBuilder<ServiceDnsResourceRecord> builder)
    {
        builder.Property(nameof(Name)).HasMaxLength(255).IsRequired().HasColumnName(nameof(Name));
        builder.HasBaseType<DnsResourceRecord>();
    }
}