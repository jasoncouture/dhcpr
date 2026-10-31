namespace Dhcpr.Server.Components.Pages.Admin.Settings;

/// <summary>
/// Line and byte-list editing for the settings forms.
/// </summary>
public interface ISettingsEdit
{
    string[] SplitLines(string text);

    string JoinLines(string[]? values);

    string JoinBytes(byte[]? values);

    bool TryParseBytes(string text, string name, out byte[] values, out string? error);
}
