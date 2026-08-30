using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core;

internal sealed class TlsConfigurationValidator : IValidateOptions<TlsConfiguration>
{
    public ValidateOptionsResult Validate(string? name, TlsConfiguration options)
        => options.TryValidate(out var error)
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(error!);
}
