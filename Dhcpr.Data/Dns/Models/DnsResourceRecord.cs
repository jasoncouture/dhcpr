using Dhcpr.Data.Abstractions;
using Dhcpr.Data.Extensions;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Dhcpr.Data.Dns.Models;

[Index(nameof(ParentId))]
[PrimaryKey(nameof(Id))]
public abstract class DnsResourceRecord : IDataRecord<DnsResourceRecord>
{
    public string Id { get; set; } = string.Empty;
    public string OwnerId { get; set; } = string.Empty;
    public required string ParentId { get; set; }
    public virtual required DnsNameRecord Parent { get; set; }


    public virtual ResourceRecordType RecordType { get; set; }
    public ResourceRecordClass Class { get; set; } = ResourceRecordClass.Any;

    public ResourceRecordSection Section { get; set; } = ResourceRecordSection.Answer;


    public TimeSpan TimeToLive { get; set; } = TimeSpan.Zero;
    public DateTimeOffset Created { get; set; }
    public DateTimeOffset Modified { get; set; }

    static void ISelfBuildingModel<DnsResourceRecord>.OnModelCreating(
        EntityTypeBuilder<DnsResourceRecord> entityBuilder)
    {
        entityBuilder.AddDataRecordValueGenerators();
        entityBuilder.HasOne<DnsNameRecord>(i => i.Parent)
            .WithMany()
            .HasForeignKey(i => i.ParentId)
            .HasPrincipalKey(i => i.Id);
        entityBuilder.HasKey(i => i.Id);
        entityBuilder.HasDiscriminator(i => i.RecordType)
            .HasValue<InterNetworkVersion4AddressResourceRecord>(ResourceRecordType.A)
            .HasValue<NameServerDnsResourceRecord>(ResourceRecordType.NS)
            .HasValue<CanonicalNameDnsResourceRecord>(ResourceRecordType.CNAME)
            .HasValue<MailExchangerDnsResourceRecord>(ResourceRecordType.MX)
            .HasValue<TextDnsResourceRecord>(ResourceRecordType.TXT)
            .HasValue<ServiceDnsResourceRecord>(ResourceRecordType.SRV)
            .HasValue<PointerDnsResourceRecord>(ResourceRecordType.PTR)
            .HasValue<InterNetworkVersion6AddressDnsResourceRecord>(ResourceRecordType.AAAA)
            .HasValue<StartOfAuthorityDnsResourceRecord>(ResourceRecordType.SOA);
    }
}