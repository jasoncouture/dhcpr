using Microsoft.Extensions.DependencyInjection;

namespace Dhcpr.Core;

public static class TaskExtensions
{
    public static async void OrphanAsync(this Task task)
    {
        await task.IgnoreExceptionsAsync().ConfigureAwait(false);
    }
    public static async Task IgnoreExceptionsAsync(this Task task)
    {
        try
        {
            await task;
        }
        catch (Exception)
        {
            // Ignored.
        }
    }

    public static async Task IgnoreExceptionsAsync(this Task task, CancellationToken cancellationToken)
    {
        try
        {
            task = task.WaitAsync(cancellationToken);
            // Keep swallowing failures if the linked wait itself is cancelled mid-flight.
            task = task.ContinueWith(static async t => await t.IgnoreExceptionsAsync());
            await task.WaitAsync(cancellationToken);
        }
        catch (Exception)
        {
            // Ignored.
        }
    }

    public static async Task<bool> OperationCancelledToBooleanAsync(this Task task)
    {
        try
        {
            await task;
            return true;
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    public static async Task<T?> ConvertExceptionsToNull<T>(this Task<T> task)
    {
        try
        {
            return await task;
        }
        catch
        {
            return default;
        }
    }

    public static async Task<T?> OperationCancelledToNull<T>(this Task<T> task)
    {
        try
        {
            return await task;
        }
        catch (OperationCanceledException)
        {
            return default;
        }
    }

    public static IServiceCollection AddAlias<TTargetService, TSourceService>(this IServiceCollection services,
        ServiceLifetime lifetime = ServiceLifetime.Scoped)
        where TSourceService : TTargetService
        where TTargetService : notnull
    {
        services.Add(ServiceDescriptor.Describe(typeof(TTargetService), s => s.GetRequiredService<TSourceService>(),
            lifetime));
        return services;
    }
}