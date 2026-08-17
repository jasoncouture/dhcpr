using Dhcpr.Dns.Core.Protocol;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed record ReferralWalkOptions(
    bool DetectSelfReferral = true,
    bool PromoteAuthoritativeAnswer = true,
    bool ServFailNonAuthoritativeApexTypes = true,
    bool FilterNsOwnerByQname = true,
    bool IgnoreGlueHopDnssecStatus = true,
    bool StopOnAuthoritativeAnswersOnly = true,
    bool UseRecursiveUnresolvedReferral = true,
    string? InitialCutApex = null,
    Func<string?, DomainMessage, CancellationToken, ValueTask<LocalReferralCut?>>? TryLocalCut = null)
{
    public static ReferralWalkOptions Recursive { get; } = new();

    public static ReferralWalkOptions Authoritative { get; } = new(
        DetectSelfReferral: false,
        PromoteAuthoritativeAnswer: false,
        ServFailNonAuthoritativeApexTypes: false,
        FilterNsOwnerByQname: false,
        IgnoreGlueHopDnssecStatus: false,
        StopOnAuthoritativeAnswersOnly: false,
        UseRecursiveUnresolvedReferral: false);
}
