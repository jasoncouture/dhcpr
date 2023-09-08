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
        while (true)
        {
            await using var transaction = await _context
                .BeginTransactionAsync(cancellationToken)
                ;

            var deleted = await _context.CacheEntries
                .Where(i => i.Expires <= message.Sent)
                .OrderBy(i => i.Id)
                .Take(100)
                .ExecuteDeleteAsync(cancellationToken)
                ;

            await transaction.CommitAsync(cancellationToken);
            
            if (deleted == 0)
            {
                break;
            }

            // ReSharper disable once StringLiteralTypo
            _logger.LogDebug("Deleted {count} dns cache entr{suffix}", deleted, deleted == 1 ? "y" : "ies");
        }
        _tracker.ScanForExpirationComplete(message.Sent);
    }
}