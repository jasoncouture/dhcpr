using System.Text;

using DnsZone.Records;

namespace Dhcpr.Dns.Core.Protocol.Zone;

/// <summary>
/// Drops RR lines DnsZone cannot parse (DNSSEC, $GENERATE, unknown types)
/// so InterNIC-style signed zones still load for the RRs we care about.
/// </summary>
public static class BindZoneUnsupportedFilter
{
    private static readonly HashSet<string> _supportedTypes =
        new(Enum.GetNames<ResourceRecordType>(), StringComparer.OrdinalIgnoreCase);

    public static string Filter(string text)
    {
        var expanded = ExpandParentheses(text);
        var sb = new StringBuilder(expanded.Length);
        foreach (var rawLine in expanded.Split('\n'))
        {
            if (ShouldKeepLine(rawLine))
            {
                sb.Append(rawLine);
                sb.Append('\n');
            }
        }

        return sb.ToString();
    }

    private static bool ShouldKeepLine(string rawLine)
    {
        var blankOwner = rawLine.Length > 0 && char.IsWhiteSpace(rawLine[0]);
        var line = StripComment(rawLine).Trim();
        if (line.Length == 0)
            return true;

        if (line.StartsWith('$'))
        {
            var directive = line[1..].Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)[0];
            return !directive.Equals("GENERATE", StringComparison.OrdinalIgnoreCase);
        }

        var tokens = Tokenize(line);
        if (tokens.Count == 0)
            return true;

        var index = 0;
        if (!blankOwner && LooksLikeOwner(tokens[0]))
            index++;

        while (index < tokens.Count)
        {
            if (IsClass(tokens[index]) || IsTtl(tokens[index]))
            {
                index++;
                continue;
            }

            break;
        }

        if (index >= tokens.Count)
            return true;

        return _supportedTypes.Contains(tokens[index]);
    }

    private static bool LooksLikeOwner(string token)
        => !IsClass(token) && !IsTtl(token) && !_supportedTypes.Contains(token);

    private static bool IsClass(string token)
        => token.Equals("IN", StringComparison.OrdinalIgnoreCase) ||
           token.Equals("CH", StringComparison.OrdinalIgnoreCase) ||
           token.Equals("HS", StringComparison.OrdinalIgnoreCase) ||
           token.Equals("CS", StringComparison.OrdinalIgnoreCase);

    private static bool IsTtl(string token)
    {
        if (token.Length == 0)
            return false;
        // integer seconds or BIND units (1h, 2d, 30m, …)
        var i = 0;
        while (i < token.Length && char.IsDigit(token[i]))
            i++;
        if (i == 0)
            return false;
        if (i == token.Length)
            return true;
        if (i != token.Length - 1)
            return false;
        return token[^1] is 's' or 'S' or 'm' or 'M' or 'h' or 'H' or 'd' or 'D' or 'w' or 'W';
    }

    private static string StripComment(string line)
    {
        var inQuotes = false;
        for (var i = 0; i < line.Length; i++)
        {
            var ch = line[i];
            if (ch == '"')
                inQuotes = !inQuotes;
            else if (ch == ';' && !inQuotes)
                return line[..i];
        }

        return line;
    }

    private static List<string> Tokenize(string line)
    {
        var tokens = new List<string>();
        var current = new StringBuilder();
        var inQuotes = false;
        foreach (var ch in line)
        {
            if (ch == '"')
            {
                inQuotes = !inQuotes;
                current.Append(ch);
                continue;
            }

            if (!inQuotes && char.IsWhiteSpace(ch))
            {
                if (current.Length > 0)
                {
                    tokens.Add(current.ToString());
                    current.Clear();
                }

                continue;
            }

            current.Append(ch);
        }

        if (current.Length > 0)
            tokens.Add(current.ToString());
        return tokens;
    }

    private static string ExpandParentheses(string text)
    {
        var sb = new StringBuilder(text.Length);
        var depth = 0;
        foreach (var ch in text)
        {
            if (ch == '(')
            {
                depth++;
                sb.Append(' ');
                continue;
            }

            if (ch == ')')
            {
                depth = Math.Max(0, depth - 1);
                sb.Append(' ');
                continue;
            }

            if (ch is '\n' or '\r' && depth > 0)
            {
                sb.Append(' ');
                continue;
            }

            sb.Append(ch);
        }

        return sb.ToString();
    }
}
