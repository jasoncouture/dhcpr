using System.Text.RegularExpressions;

namespace Dhcpr.Core;

public static partial class DomainNameValidationExtensions
{
    [GeneratedRegex(@"(?isn)^(?<name>(([a-z]{1}[a-z0-9\-]*[a-z0-9]){0,62}\.)*([a-z]{1}[a-z0-9\-]*[a-z0-9]){0,62})\.?(:(?<port>[1-6]\d{4}|[0-9]{1,4}))?$")]
    public static partial Regex GetDnsRegularExpression();

    [GeneratedRegex(@"(?isn)^[a-z]{1}([a-z0-9\-]*[a-z0-9]{1}){0,1}$")]
    public static partial Regex GetLabelRegularExpression();
    public static bool IsValidDomainName(this string domainName) => GetDnsRegularExpression().IsMatch(domainName);
    public static bool IsValidDomainNameLabel(this string label) => GetLabelRegularExpression().IsMatch(label);
}