using Dhcpr.Data.Abstractions;

using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Dhcpr.Data.Dns.Models;

public class TextDnsResourceRecord : DnsResourceRecord, ISelfBuildingModel<TextDnsResourceRecord>
{
    public string Text { get; set; } = string.Empty;

    public override ResourceRecordType RecordType
    {
        get => ResourceRecordType.TXT;
        set { }
    }

    static void ISelfBuildingModel<TextDnsResourceRecord>.OnModelCreating(
        EntityTypeBuilder<TextDnsResourceRecord> builder)
    {
        builder.Property(nameof(Text)).HasMaxLength(255).IsRequired();
        builder.HasBaseType<DnsResourceRecord>();
    }
}