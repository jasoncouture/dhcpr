namespace Dhcpr.Server.Components.Pages.Settings;

internal static class SettingsEdit
{
    public static string[] SplitLines(string text)
        => text.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    public static string JoinLines(string[]? values)
        => values is { Length: > 0 } ? string.Join('\n', values) : "";

    public static string JoinBytes(byte[]? values)
        => values is { Length: > 0 } ? string.Join(',', values) : "";

    public static bool TryParseBytes(string text, string name, out byte[] values, out string? error)
    {
        values = [];
        error = null;
        if (string.IsNullOrWhiteSpace(text))
            return true;

        var parts = text.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        values = new byte[parts.Length];
        for (var i = 0; i < parts.Length; i++)
        {
            if (byte.TryParse(parts[i], out var value))
            {
                values[i] = value;
                continue;
            }

            error = $"{name} contains an invalid byte: {parts[i]}";
            return false;
        }

        return true;
    }
}
