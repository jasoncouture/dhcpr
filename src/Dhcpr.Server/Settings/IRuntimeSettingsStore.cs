using Microsoft.Extensions.Primitives;

namespace Dhcpr.Server.Settings;

public interface IRuntimeSettingsStore
{
    RuntimeEditableSettings Current { get; }
    IChangeToken GetChangeToken();
    void ReloadIfChanged();
    Task<string?> SaveAsync(RuntimeEditableSettings settings, CancellationToken cancellationToken);
}
