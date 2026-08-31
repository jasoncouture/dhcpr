using System.Collections.Immutable;

using Dhcpr.Core;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

public sealed class CanonicalNameResolverDecorator : IDomainMessageMiddleware
{
    private const int MaxCnameDepth = 16;

    private readonly IDomainMessageMiddleware _innerMiddleware;
    private readonly IInternalDomainClient _internalClient;

    public CanonicalNameResolverDecorator(
        IDomainMessageMiddleware innerMiddleware,
        IInternalDomainClient internalClient)
    {
        _innerMiddleware = innerMiddleware;
        _internalClient = internalClient;
    }

    public async ValueTask<DomainMessage?> ProcessAsync(DomainMessageContext context,
        CancellationToken cancellationToken)
    {
        var result = await _innerMiddleware.ProcessAsync(context, cancellationToken);
        if (result is null)
            return result;

        // Directed hops are stub queries to a specific nameserver set. Chase
        // aliases only on the undirected pass so a zone-walk referral is not
        // expanded into a full CNAME tree (and BypassCache from the hop is
        // not inherited onto every remaining alias).
        if (context.UpstreamEndpoints is { Length: > 0 })
            return result;

        if (!context.DomainMessage.Flags.RecursionDesired)
            return result;

        var questionType = context.DomainMessage.Questions[0].Type;
        if (questionType is not (DomainRecordType.A or DomainRecordType.AAAA))
            return result;

        if (result.Records.Answers.All(i => i.Type != DomainRecordType.CNAME))
            return result;

        // Never trust address RRs bundled with a CNAME — chase the target ourselves.
        // Keep CNAME + covering RRSIGs so DNSSEC can authenticate each hop's alias.
        result = result with
        {
            Records = result.Records with
            {
                Answers = KeepTypesWithCoveringRrsigs(
                    result.Records.Answers,
                    DomainRecordType.CNAME)
            }
        };

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var existing in result.Records.Answers.Where(r => r.Type is DomainRecordType.CNAME))
            seen.Add(existing.Name.ToString());

        DomainMessage? lastChase = null;

        for (var depth = 0; depth < MaxCnameDepth; depth++)
        {
            if (result.Records.Answers.Any(i => i.Type == questionType))
                return FinalizeChase(result);

            var nextTarget = GetTerminalCnameTarget(result.Records.Answers);
            if (nextTarget is null)
                break;

            var targetName = nextTarget.ToString();
            if (!seen.Add(targetName))
                break; // CNAME loop

            var nextRequest = DomainMessage.CreateRequest(nextTarget, questionType);
            var nextResponse = await _internalClient.SendAsync(context, nextRequest, cancellationToken)
                .AsTask()
                .ConvertExceptionsToNull();

            if (nextResponse is null)
                return ServFail(context.DomainMessage);

            lastChase = nextResponse;

            if (nextResponse.Flags.ResponseCode is DomainResponseCode.ServerFailure
                or DomainResponseCode.Refused)
                return ServFail(context.DomainMessage);

            var chasedCnames = KeepTypesWithCoveringRrsigs(
                nextResponse.Records.Answers,
                DomainRecordType.CNAME);

            if (chasedCnames.Any(i => i.Type is DomainRecordType.CNAME))
            {
                // Nested decorator already walked the rest of the chain. Keep
                // those addresses — stripping them forces another uncached
                // multi-cut walk (directed hops set BypassCache).
                var nestedAddresses = KeepTypesWithCoveringRrsigs(
                    nextResponse.Records.Answers,
                    questionType);

                result = result with
                {
                    Records = result.Records with
                    {
                        Answers = result.Records.Answers
                            .Concat(chasedCnames)
                            .Concat(nestedAddresses)
                            .ToImmutableArray()
                    }
                };

                foreach (var cname in chasedCnames.Where(r => r.Type is DomainRecordType.CNAME))
                    seen.Add(cname.Name.ToString());

                if (nestedAddresses.Any(i => i.Type == questionType))
                {
                    return FinalizeChase(result with
                    {
                        Flags = result.Flags with { ResponseCode = DomainResponseCode.NoError }
                    });
                }

                continue;
            }

            var chasedAddresses = KeepTypesWithCoveringRrsigs(
                nextResponse.Records.Answers,
                questionType);

            if (chasedAddresses.Any(i => i.Type == questionType))
            {
                return FinalizeChase(result with
                {
                    Flags = result.Flags with { ResponseCode = DomainResponseCode.NoError },
                    Records = result.Records with
                    {
                        Answers = result.Records.Answers.Concat(chasedAddresses).ToImmutableArray()
                    }
                });
            }

            // Tip had no CNAME and no address of the requested type.
            if (nextResponse.Flags.ResponseCode is DomainResponseCode.NameError)
            {
                return FinalizeChase(result with
                {
                    Flags = result.Flags with { ResponseCode = DomainResponseCode.NameError },
                    Records = result.Records with
                    {
                        Answers = result.Records.Answers,
                        Authorities = nextResponse.Records.Authorities,
                        Additional = ImmutableArray<DomainResourceRecord>.Empty
                    }
                });
            }

            // NODATA at tip: name exists, no QTYPE — keep CNAME chain, NOERROR.
            return FinalizeChase(result with
            {
                Flags = result.Flags with { ResponseCode = DomainResponseCode.NoError },
                Records = result.Records with
                {
                    Answers = result.Records.Answers,
                    Authorities = nextResponse.Records.Authorities,
                    Additional = ImmutableArray<DomainResourceRecord>.Empty
                }
            });
        }

        // Could not complete the chase (loop / depth / missing tip).
        if (result.Records.Answers.Any(i => i.Type == questionType))
            return FinalizeChase(result);

        if (lastChase?.Flags.ResponseCode is DomainResponseCode.NameError)
        {
            return FinalizeChase(result with
            {
                Flags = result.Flags with { ResponseCode = DomainResponseCode.NameError },
                Records = result.Records with
                {
                    Authorities = lastChase.Records.Authorities,
                    Additional = ImmutableArray<DomainResourceRecord>.Empty
                }
            });
        }

        return ServFail(context.DomainMessage);
    }

    /// <summary>
    /// AD is decided by <see cref="DnssecValidationMiddleware"/> from the shared
    /// <see cref="DnssecScope"/> — only Secure when every chase hop authenticated.
    /// Clear any AD that may have ridden on an inner hop response.
    /// </summary>
    private static DomainMessage FinalizeChase(DomainMessage result)
        => result with { Flags = result.Flags with { Authentic = false } };

    private static ImmutableArray<DomainResourceRecord> KeepTypesWithCoveringRrsigs(
        ImmutableArray<DomainResourceRecord> answers,
        DomainRecordType keepType)
    {
        var owners = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var record in answers)
        {
            if (record.Type == keepType)
                owners.Add(record.Name.ToString());
        }

        if (owners.Count == 0)
            return ImmutableArray<DomainResourceRecord>.Empty;

        return answers
            .Where(r =>
                r.Type == keepType ||
                (r.Type is DomainRecordType.RRSIG &&
                 r.Data is ResourceRecordSignatureData sig &&
                 sig.TypeCovered == keepType &&
                 owners.Contains(r.Name.ToString())))
            .ToImmutableArray();
    }

    private static DomainMessage ServFail(DomainMessage request)
        => DomainMessage.CreateResponse(
            request,
            DomainResourceRecords.Empty,
            DomainResponseCode.ServerFailure);

    private static DomainLabels? GetTerminalCnameTarget(ImmutableArray<DomainResourceRecord> answers)
    {
        var targets = new Dictionary<string, DomainLabels>(StringComparer.OrdinalIgnoreCase);

        foreach (var record in answers)
        {
            if (record.Type is not DomainRecordType.CNAME || record.Data is not NameData nameData)
                continue;
            targets[record.Name.ToString()] = nameData.Name;
        }

        if (targets.Count == 0)
            return null;

        var start = targets.Keys.FirstOrDefault(owner =>
            !targets.Values.Any(t => t.ToString().Equals(owner, StringComparison.OrdinalIgnoreCase)));
        start ??= targets.Keys.First();

        var current = start;
        for (var i = 0; i < MaxCnameDepth; i++)
        {
            if (!targets.TryGetValue(current, out var next))
                return null;
            var nextName = next.ToString();
            if (!targets.ContainsKey(nextName))
                return next;
            current = nextName;
        }

        return null;
    }

    public string Name => _innerMiddleware.Name;

    public int Priority => _innerMiddleware.Priority;
}
