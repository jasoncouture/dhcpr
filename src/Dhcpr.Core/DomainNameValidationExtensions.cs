using System.Text.RegularExpressions;

namespace Dhcpr.Core;

public static partial class DomainNameValidationExtensions
{
    // RFC 1123: labels may start with a digit; LDH only; 1–63 chars; no leading/trailing hyphen.
    [GeneratedRegex(@"(?isn)^(?<name>(([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?)\.)*([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?))\.?(:(?<port>[1-6]\d{4}|[0-9]{1,4}))?$")]
    public static partial Regex GetDnsRegularExpression();

    // DNS labels: LDH + underscore (SRV/RFC 2782); single "*" for RFC 4592 wildcards. 1–63 chars.
    [GeneratedRegex(@"(?isn)^(\*|[a-z0-9_]([a-z0-9_\-]{0,61}[a-z0-9_])?)$")]
    public static partial Regex GetLabelRegularExpression();
    public static bool IsValidDomainName(this string domainName) => GetDnsRegularExpression().IsMatch(domainName);
    public static bool IsValidDomainNameLabel(this string label) => GetLabelRegularExpression().IsMatch(label);
}