using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Dhcpr.Core;

public static class ConfigurationExtensions
{
    public static IServiceCollection AddValidation<TOptions>(this IServiceCollection services, string? name = null)
        where TOptions : class, IValidateSelf
        => services.PostConfigure<TOptions>(
            name,
            options => MaybeValidateConfigurations<TOptions>(name, options)
        );

    private static void MaybeValidateConfigurations<TOptions>(string? name, TOptions obj)
        where TOptions : class, IValidateSelf
    {
        if (!obj.Validate())
            throw new OptionsValidationException(name, typeof(TOptions), new[] { "Invalid configuration" });
    }
}