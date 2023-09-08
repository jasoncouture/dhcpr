using Microsoft.EntityFrameworkCore;

namespace Dhcpr.Data.Abstractions;

static class SelfBuildingModelExtensions
{
    public static void OnModelCreating<T>(this ModelBuilder builder) where T : class, ISelfBuildingModel<T>
    {
        T.OnModelCreating(builder.Entity<T>());
    }
}