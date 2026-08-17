using Dhcpr.Dns.Core.Protocol;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed record LocalReferralCut(
    DomainMessage Message,
    bool Terminal,
    string? NextCutApex);
