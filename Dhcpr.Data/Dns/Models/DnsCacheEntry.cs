using Dhcpr.Data.Abstractions;
using Dhcpr.Data.Extensions;

using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Dhcpr.Data.Dns.Models;

public class DnsCacheEntry : IDataRecord<DnsCacheEntry>
{ 
    static void ISelfBuildingModel<DnsCacheEntry>.OnModelCreating(EntityTypeBuilder<DnsCacheEntry> builder)
    {
        builder.AddDataRecordValueGenerators();
        builder.Property(i => i.Payload).IsRequired().HasMaxLength(2048);
        builder.HasIndex(i => new { i.Name, i.Type, i.Class }).IsUnique();
        builder.Property(i => i.Name).HasMaxLength(255).IsRequired();
    }

    public string Id { get; set; } = string.Empty;
    public string Name { get; set; } = string.Empty;
    
    public ResourceRecordType Type { get; set; }
    public ResourceRecordClass Class { get; set; }
    public byte[] Payload { get; set; } = Array.Empty<byte>();
    public TimeSpan TimeToLive { get; set; }
    public DateTimeOffset Created { get; set; }
    public DateTimeOffset Modified { get; set; }
    public DateTimeOffset Expires { get; set; }
}