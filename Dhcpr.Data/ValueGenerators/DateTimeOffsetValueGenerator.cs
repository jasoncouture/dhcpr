using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.ValueGeneration;

namespace Dhcpr.Data.ValueGenerators;

public class DateTimeOffsetValueGenerator : ValueGenerator<DateTimeOffset>
{
    private readonly IProperty _property;
    private readonly bool _generateOnAdd;
    private readonly bool _generateOnModify;

    public DateTimeOffsetValueGenerator(IProperty property, bool generateOnAdd, bool generateOnModify)
    {
        _property = property;
        _generateOnAdd = generateOnAdd;
        _generateOnModify = generateOnModify;
    }

    public override DateTimeOffset Next(EntityEntry entry)
    {
        if ((entry.State is not EntityState.Added and not EntityState.Modified) ||
            (entry.State == EntityState.Added && !_generateOnAdd) ||
            (entry.State == EntityState.Modified && !_generateOnModify)
           )
        {
            var current = entry.Property(_property);
            // Not expected to  be used on non-nullable types
            return (DateTimeOffset)current.CurrentValue!;
        }

        return DateTimeOffset.Now;
    }

    public override bool GeneratesTemporaryValues => false;
}