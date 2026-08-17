using Dhcpr.Dns.Core.Protocol;

namespace Dhcpr.Dns.Core.Authoritative;

public sealed record ZoneAnswerResult(
    ZoneAnswerKind Kind,
    DomainMessage? Message,
    string? ReferralCutApex = null);
