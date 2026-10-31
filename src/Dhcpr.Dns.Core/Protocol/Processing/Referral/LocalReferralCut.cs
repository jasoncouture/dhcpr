namespace Dhcpr.Dns.Core.Protocol.Processing.Referral;

public sealed record LocalReferralCut(
    DomainMessage Message,
    bool Terminal,
    string? NextCutApex);
