using Microsoft.Extensions.Options;

namespace Dhcpr.Server;

internal sealed class OrleansConfigurationValidator : IValidateOptions<OrleansConfiguration>
{
    public ValidateOptionsResult Validate(string? name, OrleansConfiguration options)
        => options.TryValidate(out var error)
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(error!);
}
