using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Dhcpr.Data.Abstractions;

internal interface ISelfBuildingModel<T> where T : class, ISelfBuildingModel<T>
{
    abstract static void OnModelCreating(EntityTypeBuilder<T> builder);
}