using System.Net;

using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Protocol;

namespace Dhcpr.Dns.Core.Protocol.Processing;

public sealed record LocalReferralCut(
    DomainMessage Message,
    bool Terminal,
    string? NextCutApex);

public sealed record ReferralWalkOptions
{
    public static ReferralWalkOptions Recursive { get; } = new();

    public static ReferralWalkOptions Authoritative { get; } = new()
    {
        DetectSelfReferral = false,
        PromoteAuthoritativeAnswer = false,
        ServFailNonAuthoritativeApexTypes = false,
        FilterNsOwnerByQname = false,
        IgnoreGlueHopDnssecStatus = false,
        StopOnAuthoritativeAnswersOnly = false,
        UseRecursiveUnresolvedReferral = false
    };

    public bool DetectSelfReferral { get; init; } = true;
    public bool PromoteAuthoritativeAnswer { get; init; } = true;
    public bool ServFailNonAuthoritativeApexTypes { get; init; } = true;
    public bool FilterNsOwnerByQname { get; init; } = true;
    public bool IgnoreGlueHopDnssecStatus { get; init; } = true;
    public bool StopOnAuthoritativeAnswersOnly { get; init; } = true;
    public bool UseRecursiveUnresolvedReferral { get; init; } = true;
    public string? InitialCutApex { get; init; }

    public Func<string?, DomainMessage, CancellationToken, ValueTask<LocalReferralCut?>>? TryLocalCut
    {
        get;
        init;
    }
}

public interface IReferralWalker
{
    ValueTask<DomainMessage> FollowAsync(
        DomainMessageContext context,
        DomainMessage request,
        PooledList<IPEndPoint> endPoints,
        CancellationToken cancellationToken,
        ReferralWalkOptions? options = null);

    ValueTask<bool> TrySeedEndpointsAsync(
        DomainMessageContext context,
        DomainMessage referral,
        PooledList<IPEndPoint> endPoints,
        CancellationToken cancellationToken,
        ReferralWalkOptions? options = null);

    ValueTask<IReadOnlyList<IPAddress>> ResolveNameserverAddressesAsync(
        DomainMessageContext context,
        IReadOnlyList<string> nsNames,
        CancellationToken cancellationToken,
        bool ignoreDnssecStatus = true);

    IEnumerable<string> GetNameserverNames(IEnumerable<DomainResourceRecord> records);

    IEnumerable<string> GetNameserverNames(
        IEnumerable<DomainResourceRecord> records,
        DomainLabels qname);

    IEnumerable<IPAddress> GetGlueAddresses(
        IEnumerable<DomainResourceRecord> records,
        HashSet<string> nsNames);
}
