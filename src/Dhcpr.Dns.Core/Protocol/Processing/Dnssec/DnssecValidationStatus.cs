namespace Dhcpr.Dns.Core.Protocol.Processing.Dnssec;

public enum DnssecValidationStatus
{
    Unchecked,
    Secure,
    Insecure,
    Bogus,
    Indeterminate
}
