using Dhcpr.Data.Abstractions;
using Dhcpr.Data.ValueGenerators;

using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Dhcpr.Data.Extensions;

public static class EntityTypeBuilderExtensions
{
    internal static void AddDataRecordValueGenerators<T>(this EntityTypeBuilder<T> builder)
        where T : class, IDataRecord<T>
    {
        builder.Property(i => i.Id).HasValueGenerator<StringIdValueGenerator>()
            .HasValueGenerator((p, e) => new StringIdValueGenerator(p));
        builder.Property(i => i.Modified)
            .HasValueGenerator((p, e) =>
                new DateTimeOffsetValueGenerator(p, generateOnAdd: true, generateOnModify: true));
        builder.Property(i => i.Created)
            .HasValueGenerator((p, e) =>
                new DateTimeOffsetValueGenerator(p, generateOnAdd: true, generateOnModify: false));
    }
}