﻿// <auto-generated />
using Dhcpr.Data;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Infrastructure;
using Microsoft.EntityFrameworkCore.Storage.ValueConversion;

#nullable disable

namespace Dhcpr.Data.Migrations
{
    [DbContext(typeof(DataContext))]
    partial class DataContextModelSnapshot : ModelSnapshot
    {
        protected override void BuildModel(ModelBuilder modelBuilder)
        {
#pragma warning disable 612, 618
            modelBuilder.HasAnnotation("ProductVersion", "7.0.10");

            modelBuilder.Entity("Dhcpr.Data.Dns.Models.DnsNameRecord", b =>
                {
                    b.Property<string>("Id")
                        .HasColumnType("TEXT");

                    b.Property<long>("Created")
                        .HasColumnType("INTEGER");

                    b.Property<long>("Modified")
                        .HasColumnType("INTEGER");

                    b.Property<string>("Name")
                        .IsRequired()
                        .HasMaxLength(255)
                        .HasColumnType("TEXT")
                        .IsFixedLength(false);

                    b.Property<bool>("NxDomainIfNoRecords")
                        .HasColumnType("INTEGER");

                    b.HasKey("Id");

                    b.HasIndex("Name")
                        .IsUnique();

                    b.ToTable("DnsNameRecord");
                });

            modelBuilder.Entity("Dhcpr.Data.Dns.Models.DnsResourceRecord", b =>
                {
                    b.Property<string>("Id")
                        .HasColumnType("TEXT");

                    b.Property<int>("Class")
                        .HasColumnType("INTEGER");

                    b.Property<long>("Created")
                        .HasColumnType("INTEGER");

                    b.Property<long>("Modified")
                        .HasColumnType("INTEGER");

                    b.Property<string>("OwnerId")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<string>("ParentId")
                        .IsRequired()
                        .HasColumnType("TEXT");

                    b.Property<int>("RecordType")
                        .HasColumnType("INTEGER");

                    b.Property<int>("Section")
                        .HasColumnType("INTEGER");

                    b.Property<double>("TimeToLive")
                        .HasColumnType("REAL");

                    b.HasKey("Id");

                    b.HasIndex("ParentId");

                    b.ToTable("DnsResourceRecord");

                    b.HasDiscriminator<int>("RecordType");

                    b.UseTphMappingStrategy();
                });

            modelBuilder.Entity("Dhcpr.Data.Dns.Models.CanonicalNameDnsResourceRecord", b =>
                {
                    b.HasBaseType("Dhcpr.Data.Dns.Models.DnsResourceRecord");

                    b.Property<string>("Name")
                        .IsRequired()
                        .ValueGeneratedOnUpdateSometimes()
                        .HasMaxLength(255)
                        .HasColumnType("TEXT")
                        .HasColumnName("Name");

                    b.HasDiscriminator().HasValue(5);
                });

            modelBuilder.Entity("Dhcpr.Data.Dns.Models.InterNetworkVersion4AddressResourceRecord", b =>
                {
                    b.HasBaseType("Dhcpr.Data.Dns.Models.DnsResourceRecord");

                    b.Property<byte[]>("InterNetworkVersion4Address")
                        .IsRequired()
                        .HasMaxLength(4)
                        .HasColumnType("BLOB")
                        .IsFixedLength();

                    b.HasDiscriminator().HasValue(1);
                });

            modelBuilder.Entity("Dhcpr.Data.Dns.Models.InterNetworkVersion6AddressDnsResourceRecord", b =>
                {
                    b.HasBaseType("Dhcpr.Data.Dns.Models.DnsResourceRecord");

                    b.Property<byte[]>("InterNetworkVersion6Address")
                        .IsRequired()
                        .HasMaxLength(16)
                        .HasColumnType("BLOB")
                        .IsFixedLength();

                    b.HasDiscriminator().HasValue(28);
                });

            modelBuilder.Entity("Dhcpr.Data.Dns.Models.MailExchangerDnsResourceRecord", b =>
                {
                    b.HasBaseType("Dhcpr.Data.Dns.Models.DnsResourceRecord");

                    b.Property<string>("Name")
                        .IsRequired()
                        .ValueGeneratedOnUpdateSometimes()
                        .HasMaxLength(255)
                        .HasColumnType("TEXT")
                        .HasColumnName("Name");

                    b.Property<ushort>("Preference")
                        .HasColumnType("INTEGER");

                    b.HasDiscriminator().HasValue(15);
                });

            modelBuilder.Entity("Dhcpr.Data.Dns.Models.NameServerDnsResourceRecord", b =>
                {
                    b.HasBaseType("Dhcpr.Data.Dns.Models.DnsResourceRecord");

                    b.Property<string>("Name")
                        .IsRequired()
                        .ValueGeneratedOnUpdateSometimes()
                        .HasMaxLength(255)
                        .HasColumnType("TEXT")
                        .HasColumnName("Name");

                    b.HasDiscriminator().HasValue(2);
                });

            modelBuilder.Entity("Dhcpr.Data.Dns.Models.PointerDnsResourceRecord", b =>
                {
                    b.HasBaseType("Dhcpr.Data.Dns.Models.DnsResourceRecord");

                    b.Property<string>("Name")
                        .IsRequired()
                        .ValueGeneratedOnUpdateSometimes()
                        .HasMaxLength(255)
                        .HasColumnType("TEXT")
                        .HasColumnName("Name");

                    b.HasDiscriminator().HasValue(12);
                });

            modelBuilder.Entity("Dhcpr.Data.Dns.Models.ServiceDnsResourceRecord", b =>
                {
                    b.HasBaseType("Dhcpr.Data.Dns.Models.DnsResourceRecord");

                    b.Property<string>("Name")
                        .IsRequired()
                        .ValueGeneratedOnUpdateSometimes()
                        .HasMaxLength(255)
                        .HasColumnType("TEXT")
                        .HasColumnName("Name");

                    b.Property<ushort>("Port")
                        .HasColumnType("INTEGER");

                    b.Property<ushort>("Priority")
                        .HasColumnType("INTEGER");

                    b.Property<ushort>("Weight")
                        .HasColumnType("INTEGER");

                    b.HasDiscriminator().HasValue(33);
                });

            modelBuilder.Entity("Dhcpr.Data.Dns.Models.StartOfAuthorityDnsResourceRecord", b =>
                {
                    b.HasBaseType("Dhcpr.Data.Dns.Models.DnsResourceRecord");

                    b.Property<string>("Domain")
                        .IsRequired()
                        .ValueGeneratedOnUpdateSometimes()
                        .HasMaxLength(255)
                        .HasColumnType("TEXT")
                        .HasColumnName("Name");

                    b.Property<double>("Expire")
                        .HasColumnType("REAL");

                    b.Property<string>("Master")
                        .IsRequired()
                        .HasMaxLength(255)
                        .HasColumnType("TEXT");

                    b.Property<double>("MinTtl")
                        .HasColumnType("REAL");

                    b.Property<double>("Refresh")
                        .HasColumnType("REAL");

                    b.Property<string>("Responsible")
                        .IsRequired()
                        .HasMaxLength(255)
                        .HasColumnType("TEXT");

                    b.Property<double>("Retry")
                        .HasColumnType("REAL");

                    b.Property<long>("Serial")
                        .HasColumnType("INTEGER");

                    b.Property<double>("Ttl")
                        .HasColumnType("REAL");

                    b.HasDiscriminator().HasValue(6);
                });

            modelBuilder.Entity("Dhcpr.Data.Dns.Models.TextDnsResourceRecord", b =>
                {
                    b.HasBaseType("Dhcpr.Data.Dns.Models.DnsResourceRecord");

                    b.Property<string>("Text")
                        .IsRequired()
                        .HasMaxLength(255)
                        .HasColumnType("TEXT");

                    b.HasDiscriminator().HasValue(16);
                });

            modelBuilder.Entity("Dhcpr.Data.Dns.Models.DnsResourceRecord", b =>
                {
                    b.HasOne("Dhcpr.Data.Dns.Models.DnsNameRecord", "Parent")
                        .WithMany()
                        .HasForeignKey("ParentId")
                        .OnDelete(DeleteBehavior.Cascade)
                        .IsRequired();

                    b.Navigation("Parent");
                });
#pragma warning restore 612, 618
        }
    }
}
