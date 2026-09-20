using System.Diagnostics.CodeAnalysis;
using System.Text.RegularExpressions;

using Dhcpr.Dns.Core.Protocol;

namespace Dhcpr.Dns.Core;

/// <summary>
/// Suffix match (name + subdomains) or a .NET regex.
/// A line is a regex when it starts with <c>/</c> or contains
/// <c>^ $ + * ? [ ( { | \</c>. DNS matching is always case-insensitive.
/// </summary>
public sealed class BlackholeRuleSet
{
    public static BlackholeRuleSet Empty { get; } = new([], []);

    private static readonly TimeSpan MatchTimeout = TimeSpan.FromMilliseconds(50);
    private static readonly RegexOptions PatternOptions =
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking;

    private readonly string[] _suffixes;
    private readonly Regex[] _patterns;

    private BlackholeRuleSet(string[] suffixes, Regex[] patterns)
    {
        _suffixes = suffixes;
        _patterns = patterns;
    }

    public bool IsEmpty => _suffixes.Length == 0 && _patterns.Length == 0;

    public static bool TryCreate(
        string[] entries,
        [NotNullWhen(false)] out string? error,
        out BlackholeRuleSet rules)
    {
        var suffixes = new List<string>();
        var patterns = new List<Regex>();
        for (var i = 0; i < entries.Length; i++)
        {
            var entry = entries[i];
            if (!LooksLikeRegex(entry))
            {
                suffixes.Add(entry);
                continue;
            }

            if (!TryCompile(entry, i, out error, out var regex))
            {
                rules = Empty;
                return false;
            }

            patterns.Add(regex);
        }

        error = null;
        rules = suffixes.Count == 0 && patterns.Count == 0
            ? Empty
            : new BlackholeRuleSet(suffixes.ToArray(), patterns.ToArray());
        return true;
    }

    public bool Matches(DomainLabels name) => Matches(name.ToString());

    public bool Matches(string qname)
    {
        foreach (var suffix in _suffixes)
        {
            if (qname.Equals(suffix, StringComparison.OrdinalIgnoreCase))
                return true;
            if (qname.Length > suffix.Length + 1 &&
                qname.EndsWith($".{suffix}", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        foreach (var pattern in _patterns)
        {
            if (pattern.IsMatch(qname))
                return true;
        }

        return false;
    }

    public static bool LooksLikeRegex(string entry)
    {
        if (entry.StartsWith('/'))
            return true;

        foreach (var c in entry)
        {
            if (c is '^' or '$' or '+' or '*' or '?' or '[' or '(' or '{' or '|' or '\\')
                return true;
        }

        return false;
    }

    private static bool TryCompile(
        string entry,
        int index,
        [NotNullWhen(false)] out string? error,
        [NotNullWhen(true)] out Regex? regex)
    {
        if (!TryGetPattern(entry, index, out error, out var pattern))
        {
            regex = null;
            return false;
        }

        try
        {
            regex = new Regex(pattern, PatternOptions, MatchTimeout);
            return true;
        }
        catch (ArgumentException ex)
        {
            error = $"DNS:BlackholeDomains[{index}] is not a valid regex: {ex.Message}";
            regex = null;
            return false;
        }
    }

    private static bool TryGetPattern(
        string entry,
        int index,
        [NotNullWhen(false)] out string? error,
        [NotNullWhen(true)] out string? pattern)
    {
        if (!entry.StartsWith('/'))
        {
            error = null;
            pattern = entry;
            return true;
        }

        if (entry.Length < 2 || !entry.EndsWith('/'))
        {
            error = $"DNS:BlackholeDomains[{index}] is a regex missing a closing '/'";
            pattern = null;
            return false;
        }

        pattern = entry[1..^1];
        if (pattern.Length == 0)
        {
            error = $"DNS:BlackholeDomains[{index}] is an empty regex";
            pattern = null;
            return false;
        }

        error = null;
        return true;
    }
}
