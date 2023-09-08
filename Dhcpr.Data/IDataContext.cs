using System.Data;

using Dhcpr.Data.Dns.Models;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace Dhcpr.Data;

public interface IDataContext
{
    public DbSet<DnsResourceRecord> ResourceRecords { get; }
    public DbSet<DnsNameRecord> NameRecords { get; }
    public DbSet<DnsCacheEntry> CacheEntries { get; }
    public Task<int> SaveChangesAsync(CancellationToken cancellationToken);

    Task<IDbContextTransaction> BeginTransactionAsync(IsolationLevel isolationLevel,
        CancellationToken cancellationToken);

    Task<IDbContextTransaction> BeginTransactionAsync(CancellationToken cancellationToken)
        => BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
}