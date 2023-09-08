using Dhcpr.Data.Abstractions;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Dhcpr.Data.Dns.Models;

public class MailExchangerDnsResourceRecord : DnsResourceRecord, ISelfBuildingModel<MailExchangerDnsResourceRecord>
{
    public ushort Preference { get; set; }
    public string Name { get; set; } = string.Empty;

    public override ResourceRecordType RecordType
    {
        get => ResourceRecordType.MX;
        set { }
    }

    static void ISelfBuildingModel<MailExchangerDnsResourceRecord>.OnModelCreating(
        EntityTypeBuilder<MailExchangerDnsResourceRecord> builder)
    {
        builder.Property(nameof(Name)).HasMaxLength(255).IsRequired().HasColumnName(nameof(Name));
        builder.HasBaseType<DnsResourceRecord>();
    }
}