using System.Diagnostics.CodeAnalysis;

using Dhcpr.Core;

using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.ChangeTracking;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Dhcpr.Data;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddDatabaseServices(this IServiceCollection services)
    {
        services.AddQueueProcessor<HeartBeatMessage, DatabaseExpirationScannerService>();
        services.AddDbContextPool<IDataContext, DataContext>(ConfigureDataContext);
        services.AddSingleton<IInterceptor, DataRecordAutomaticFieldsSaveChangesInterceptor>();
        return services;
    }

    private static void ConfigureDataContext(IServiceProvider services, DbContextOptionsBuilder optionsBuilder)
    {
        var configuration = services.GetRequiredService<IConfiguration>();
        var interceptors = services.GetServices<IInterceptor>().ToArray();
        optionsBuilder.UseSqlite(configuration.GetConnectionString("Default"));
        if (interceptors.Length > 0)
            optionsBuilder.AddInterceptors(interceptors);
    }
}