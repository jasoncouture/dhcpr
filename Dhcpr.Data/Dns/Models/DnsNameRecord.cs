using System.ComponentModel.DataAnnotations.Schema;

using Dhcpr.Data.Abstractions;
using Dhcpr.Data.Extensions;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Dhcpr.Data.Dns.Models;

public class DnsNameRecord : IDataRecord<DnsNameRecord>
{
    [DatabaseGenerated(DatabaseGeneratedOption.None)]
    public string Id { get; set; } = string.Empty;

    public string Name { get; set; } = string.Empty;

    public bool NxDomainIfNoRecords { get; set; } = false;

    public DateTimeOffset Created { get; set; } = DateTimeOffset.Now;
    public DateTimeOffset Modified { get; set; } = DateTimeOffset.Now;

    static void ISelfBuildingModel<DnsNameRecord>.OnModelCreating(EntityTypeBuilder<DnsNameRecord> entityBuilder)
    {
        entityBuilder.AddDataRecordValueGenerators();
        entityBuilder.HasKey(i => i.Id);
        entityBuilder.HasIndex(i => i.Name).IsUnique();
        entityBuilder.Property(i => i.Name)
            .IsRequired()
            .HasMaxLength(255)
            .IsFixedLength(false);
    }
}