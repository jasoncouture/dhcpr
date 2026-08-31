using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace Dhcpr.Server.Settings;

internal sealed class RuntimeSettingsChangeTokenSource<TOptions>(IRuntimeSettingsStore store)
    : IOptionsChangeTokenSource<TOptions>
{
    public string Name => Options.DefaultName;
    public IChangeToken GetChangeToken() => store.GetChangeToken();
}