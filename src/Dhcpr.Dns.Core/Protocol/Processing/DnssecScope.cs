namespace Dhcpr.Dns.Core.Protocol.Processing;

public enum DnssecValidationStatus
{
    Unchecked,
    Secure,
    Insecure,
    Bogus,
    Indeterminate
}

public sealed class DnssecScope
{
    public DnssecValidationStatus Status { get; set; } = DnssecValidationStatus.Unchecked;
    
    // We can add additional tracking state here as we build out the validator, 
    // e.g., the current zone cuts, authenticated keys, etc.
}
