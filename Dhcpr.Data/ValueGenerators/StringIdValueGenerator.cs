using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Metadata;
using Microsoft.EntityFrameworkCore.ValueGeneration;

namespace Dhcpr.Data.ValueGenerators;

public sealed class StringIdValueGenerator : ValueGenerator<string>
{
    private readonly IProperty _property;

    public StringIdValueGenerator(IProperty property)
    {
        _property = property;
    }

    public override string Next(EntityEntry entry)
    {
        var currentValue = entry.Property(_property).CurrentValue as string;
        if (!string.IsNullOrWhiteSpace(currentValue)) return currentValue;
        if (entry.State != EntityState.Added) return currentValue!;
        currentValue = Guid.NewGuid().ToString("n").Substring(0, 8);
        return currentValue;
    }

    public override bool GeneratesTemporaryValues => false;
}