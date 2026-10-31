namespace Dhcpr.Dns.Core.Protocol.Processing;

public enum DnssecValidationStatus
{
    Unchecked,
    Secure,
    Insecure,
    Bogus,
    Indeterminate
}
