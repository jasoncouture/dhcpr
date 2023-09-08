using Dhcpr.Core.Linq;
using Dhcpr.Data.Abstractions;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Diagnostics;

namespace Dhcpr.Data;

public sealed class DataRecordAutomaticFieldsSaveChangesInterceptor : SaveChangesInterceptor
{
    public override InterceptionResult<int> SavingChanges(
        DbContextEventData eventData,
        InterceptionResult<int> result
    )
    {
        var context = eventData.Context;
        if (context is null)
            return result;
        using var changes = context.ChangeTracker.Entries()
            .Where(i =>
                i.State is EntityState.Added or EntityState.Modified &&
                i.Entity.GetType().IsAssignableTo(typeof(IDataRecordBase))
            )
            .ToPooledList();
        if (changes is { Count: 0 })
            return result;

        foreach (var change in changes)
        {
            if (change.State is not EntityState.Added and not EntityState.Modified)
                continue;

            if (change.Entity is not IDataRecordBase dataRecord)
                continue;

            try
            {
                dataRecord.Modified = DateTimeOffset.Now;
                if (change.State != EntityState.Added)
                    continue;

                dataRecord.Created = dataRecord.Modified;
                if (string.IsNullOrWhiteSpace(dataRecord.Id))
                    dataRecord.Id = Guid.NewGuid().ToString("n")[..7];
            }
            finally
            {
                // If the object was updated with a non-entity object
                // we want to update only what we touched. Which is why
                // we don't just pass dataRecord directly.

                // By doing it this way, EF will reflect over this anonymous type
                // and match these 3 properties only.

                // This should also be more efficient than calling DetectChanges at the end.
                change.CurrentValues.SetValues(new { dataRecord.Id, dataRecord.Created, dataRecord.Modified });
            }
        }

        return result;
    }

    public override ValueTask<InterceptionResult<int>> SavingChangesAsync(
        DbContextEventData eventData,
        InterceptionResult<int> result,
        CancellationToken cancellationToken = default
    )
    {
        return ValueTask.FromResult(SavingChanges(eventData, result));
    }
}