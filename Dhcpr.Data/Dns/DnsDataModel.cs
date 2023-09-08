using Dhcpr.Data.Abstractions;
using Dhcpr.Data.Dns.Models;

using Microsoft.EntityFrameworkCore;

namespace Dhcpr.Data.Dns;

static class DnsDataModel
{
    private static void OnModelCreating<T>(ModelBuilder builder) where T : class, ISelfBuildingModel<T> =>
        builder.OnModelCreating<T>();

    public static void OnModelCreating(ModelBuilder modelBuilder)
    {
        OnModelCreating<DnsNameRecord>(modelBuilder);
        OnModelCreating<DnsResourceRecord>(modelBuilder);

        OnModelCreating<NameServerDnsResourceRecord>(modelBuilder);
        OnModelCreating<CanonicalNameDnsResourceRecord>(modelBuilder);
        OnModelCreating<MailExchangerDnsResourceRecord>(modelBuilder);
        OnModelCreating<TextDnsResourceRecord>(modelBuilder);
        OnModelCreating<ServiceDnsResourceRecord>(modelBuilder);
        OnModelCreating<PointerDnsResourceRecord>(modelBuilder);
        OnModelCreating<InterNetworkVersion4AddressResourceRecord>(modelBuilder);
        OnModelCreating<InterNetworkVersion6AddressDnsResourceRecord>(modelBuilder);
        OnModelCreating<StartOfAuthorityDnsResourceRecord>(modelBuilder);
        OnModelCreating<DnsCacheEntry>(modelBuilder);
    }
}