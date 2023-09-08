using System.Data;

using Dhcpr.Data.Dns;
using Dhcpr.Data.Dns.Models;
using Dhcpr.Data.ValueConverters;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.Storage;

namespace Dhcpr.Data;

public class DataContext : DbContext, IDataContext
{
    public DataContext(DbContextOptions<DataContext> options) : base(options)
    {
        
    }

    public async Task<IDbContextTransaction> BeginTransactionAsync(CancellationToken cancellationToken)
    {
        return await Database.BeginTransactionAsync(cancellationToken).ConfigureAwait(false);
    }
    public async Task<IDbContextTransaction> BeginTransactionAsync(IsolationLevel isolationLevel, CancellationToken cancellationToken)
    {
        return await Database.BeginTransactionAsync(isolationLevel, cancellationToken).ConfigureAwait(false);
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        DnsDataModel.OnModelCreating(modelBuilder);
        foreach (var entity in modelBuilder.Model.GetEntityTypes())
        {
            // Iterate all properties, and set value converters.
            foreach (var property in entity.GetProperties().Where(i => i.DeclaringEntityType == entity))
            {
                HandleDateTimeOffsetProperty(modelBuilder, entity, property);
                //HandleEnumProperty(modelBuilder, entity, property);
                HandleTimeSpanProperty(modelBuilder, entity, property);
            }
        }

        base.OnModelCreating(modelBuilder);
    }

    private void HandleTimeSpanProperty(ModelBuilder modelBuilder, IMutableEntityType entity, IMutableProperty property)
    {
        if (property.ClrType != typeof(TimeSpan))
            return;

        modelBuilder.Entity(entity.Name)
            .Property(property.Name)
            .HasConversion(TimeSpanValueConverter.Instance);
    }

    private void HandleDateTimeOffsetProperty(ModelBuilder modelBuilder, IMutableEntityType entity,
        IMutableProperty property)
    {
        if (property.ClrType != typeof(DateTimeOffset))
            return;
        
        modelBuilder
            .Entity(entity.Name)
            .Property(property.Name)
            .HasConversion(UnixTimestampValueConverter.Instance);
    }

    public DbSet<DnsResourceRecord> ResourceRecords { get; init; }
    public DbSet<DnsNameRecord> NameRecords { get; init; }
    public DbSet<DnsCacheEntry> CacheEntries { get; init; }
}