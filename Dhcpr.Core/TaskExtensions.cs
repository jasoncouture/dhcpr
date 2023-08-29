using Microsoft.Extensions.DependencyInjection;

namespace Dhcpr.Core;

public static class TaskExtensions
{
    public static async Task IgnoreExceptionsAsync(this Task task, CancellationToken? cancellationToken = default)
    {
        try
        {
            task = task.WaitAsync(cancellationToken ?? CancellationToken.None);
            if (cancellationToken is not null)
                task = task.ContinueWith(async t => await t.IgnoreExceptionsAsync().ConfigureAwait(false));
            await task.WaitAsync(cancellationToken ?? CancellationToken.None).ConfigureAwait(false);
        }
        catch (Exception)
        {
            // Ignored.
        }
    }

    public static async Task<bool> OperationCancelledToBoolean(this Task task)
    {
        try
        {
            await task.ConfigureAwait(false);
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
            return await task.ConfigureAwait(false);
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
            return await task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return default;
        }
    }

    public static IServiceCollection AddAlias<TTargetService, TSourceService>(this IServiceCollection services,
        ServiceLifetime lifetime = ServiceLifetime.Singleton)
        where TSourceService : TTargetService
        where TTargetService : notnull
    {
        services.Add(ServiceDescriptor.Describe(typeof(TTargetService), s => s.GetRequiredService<TSourceService>(),
            lifetime));
        return services;
    }
}