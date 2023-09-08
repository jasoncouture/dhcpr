using Dhcpr.Data.Abstractions;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Dhcpr.Data.Dns.Models;

public class StartOfAuthorityDnsResourceRecord : DnsResourceRecord, IDataRecord<StartOfAuthorityDnsResourceRecord>
{
    public string Domain { get; set; } = string.Empty;
    public string Master { get; set; } = string.Empty;
    public string Responsible { get; set; } = string.Empty;
    public long Serial { get; set; }
    public TimeSpan Refresh { get; set; }
    public TimeSpan Retry { get; set; }
    public TimeSpan Expire { get; set; }
    public TimeSpan MinTtl { get; set; }
    public TimeSpan Ttl { get; set; }

    public static void OnModelCreating(EntityTypeBuilder<StartOfAuthorityDnsResourceRecord> builder)
    {
        throw new NotImplementedException();
    }


    static void ISelfBuildingModel<StartOfAuthorityDnsResourceRecord>.OnModelCreating(
        EntityTypeBuilder<StartOfAuthorityDnsResourceRecord> entityBuilder)
    {
        entityBuilder.Property(i => i.Master)
            .HasMaxLength(255)
            .IsRequired();
        entityBuilder.Property(i => i.Domain)
            .HasMaxLength(255)
            .IsRequired()
            .HasColumnName(nameof(CanonicalNameDnsResourceRecord.Name));
        entityBuilder.Property(i => i.Responsible)
            .HasMaxLength(255)
            .IsRequired();
    }
}