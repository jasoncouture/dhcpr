using System.Data;

using Dhcpr.Core;
using Dhcpr.Core.Queue;

using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Dhcpr.Data;

internal class DatabaseExpirationScannerService : IQueueMessageProcessor<HeartBeatMessage>
{
    private readonly IDatabaseExpirationTracker _tracker;
    private readonly IDataContext _context;
    private readonly ILogger<DatabaseExpirationScannerService> _logger;

    public DatabaseExpirationScannerService(IDatabaseExpirationTracker tracker, IDataContext context,
        ILogger<DatabaseExpirationScannerService> logger)
    {
        _tracker = tracker;
        _context = context;
        _logger = logger;
    }

    public async Task ProcessMessageAsync(HeartBeatMessage message, CancellationToken cancellationToken)
    {
        if (!_tracker.ShouldScanForExpirations(message.Sent)) return;
        int deleted = 0;
        for (var x = 0; x < 5000; x++)
        {
            await using var transaction = await _context
                .BeginTransactionAsync(IsolationLevel.ReadCommitted, cancellationToken)
                .ConfigureAwait(false);
            var next = await _context.CacheEntries
                .AsNoTracking()
                .FirstOrDefaultAsync(i => i.Expires <= message.Sent, cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            if (next is null)
            {
                deleted = x;
                break;
            }

            await _context.CacheEntries.Where(i => i.Id == next.Id)
                .ExecuteDeleteAsync(cancellationToken: cancellationToken)
                .ConfigureAwait(false);
            await _context.SaveChangesAsync(cancellationToken).ConfigureAwait(false);
            await transaction.CommitAsync(cancellationToken);
        }

        // ReSharper disable once StringLiteralTypo
        _logger.LogDebug("Deleted {count} dns cache entr{suffix}", deleted, deleted == 1 ? "y" : "ies");
    }
}