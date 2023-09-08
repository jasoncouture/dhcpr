using System.Data;

using Dhcpr.Data;
using Dhcpr.Dns.Core.Resolvers.Caching;

using DNS.Protocol;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace Dhcpr.Dns.Core;

public sealed class DatabaseCacheItemLoader : IHostedService
{
    private readonly IServiceScopeFactory _serviceScopeFactory;
    private readonly IDnsMemoryCacheWriter _memoryCacheWriter;
    private readonly ILogger<DatabaseCacheItemLoader> _logger;

    public DatabaseCacheItemLoader(
        IServiceScopeFactory serviceScopeFactory,
        IDnsMemoryCacheWriter memoryCacheWriter,
        ILogger<DatabaseCacheItemLoader> logger
    )
    {
        _serviceScopeFactory = serviceScopeFactory;
        _memoryCacheWriter = memoryCacheWriter;
        _logger = logger;
    }

    public async Task StartAsync(CancellationToken cancellationToken)
    {
        await using var scope = _serviceScopeFactory.CreateAsyncScope();
        var context = scope.ServiceProvider.GetRequiredService<IDataContext>();
        var memoryCache = scope.ServiceProvider.GetRequiredService<IMemoryCache>();
        await using var transaction = await context
            .BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken);
        var now = DateTimeOffset.Now.AddMinutes(1);
        await foreach (var entry in context.CacheEntries
                           .AsAsyncEnumerable()
                           .WithCancellation(cancellationToken)
                           
                      )
        {
            if (entry.Expires < now) continue;
            var response = entry.ToResponse();
            if (response is null)
            {
                context.CacheEntries.Entry(entry).State = EntityState.Deleted;
                continue;
            }

            var key = new QueryCacheKey(
                entry.Name.ToLower(),
                (RecordType)entry.Type,
                (RecordClass)entry.Class);
            _memoryCacheWriter.AddToMemoryCache(key, response, entry.Expires - now);
            _logger.LogInformation("Loaded cache entry {key}", key);
        }

        await context.CacheEntries.Where(i => i.Expires < now).ExecuteDeleteAsync(cancellationToken)
            ;
        await transaction.CommitAsync(cancellationToken);
    }

    public Task StopAsync(CancellationToken cancellationToken)
        => Task.CompletedTask;
}