using Microsoft.Extensions.Options;

namespace Dhcpr.Dns.Core;

internal sealed class DnsConfigurationValidator : IValidateOptions<DnsConfiguration>
{
    public ValidateOptionsResult Validate(string? name, DnsConfiguration options)
        => options.TryValidate(out var error)
            ? ValidateOptionsResult.Success
            : ValidateOptionsResult.Fail(error!);
}
