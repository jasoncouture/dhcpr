using Dhcpr.Data.Dns.Models;

using Microsoft.EntityFrameworkCore;

namespace Dhcpr.Data;

public interface IDataContext
{
    public DbSet<DnsResourceRecord> ResourceRecords { get; }
    public DbSet<DnsNameRecord> NameRecords { get; }
    public Task<int> SaveChangesAsync(CancellationToken cancellationToken);
}