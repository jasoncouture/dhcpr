using System.Collections.Immutable;

using Dhcpr.Core;
using Dhcpr.Core.Linq;
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
        result = result with { Flags = result.Flags with { RecursionAvailable = true } };
        if (!context.DomainMessage.Flags.RecursionDesired)
            return result;

        var questionType = context.DomainMessage.Questions[0].Type;
        if (questionType is not (DomainRecordType.A or DomainRecordType.AAAA))
            return result;

        if (result.Records.Answers.All(i => i.Type != DomainRecordType.CNAME))
            return result;

        // Never trust address RRs bundled with a CNAME — chase the target ourselves.
        result = result with
        {
            Records = result.Records with
            {
                Answers = result.Records.Answers
                    .Where(i => i.Type is DomainRecordType.CNAME)
                    .ToImmutableArray()
            }
        };

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var existing in result.Records.Answers.Where(r => r.Type is DomainRecordType.CNAME))
        {
            if (existing.Data is NameData existingTarget)
                seen.Add(existing.Name.ToString());
        }

        for (var depth = 0; depth < MaxCnameDepth; depth++)
        {
            if (result.Records.Answers.Any(i => i.Type == questionType))
                break;

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

            if (nextResponse is null || nextResponse.Records.Answers.Length == 0)
                break;

            var chasedCnames = nextResponse.Records.Answers
                .Where(i => i.Type is DomainRecordType.CNAME)
                .ToImmutableArray();

            if (chasedCnames.Length > 0)
            {
                // Further CNAMEs: keep the chain, ignore any bundled addresses, continue.
                result = result with
                {
                    Records = result.Records with
                    {
                        Answers = result.Records.Answers.Concat(chasedCnames).ToImmutableArray()
                    }
                };

                foreach (var cname in chasedCnames)
                    seen.Add(cname.Name.ToString());
                continue;
            }

            var chasedAddresses = nextResponse.Records.Answers
                .Where(i => i.Type == questionType)
                .ToImmutableArray();
            if (chasedAddresses.Length == 0)
                break;

            result = result with
            {
                Records = result.Records with
                {
                    Answers = result.Records.Answers.Concat(chasedAddresses).ToImmutableArray()
                }
            };
            break;
        }

        return result;
    }

    private static DomainLabels? GetTerminalCnameTarget(ImmutableArray<DomainResourceRecord> answers)
    {
        // Follow the chain already in Answers to the current tip.
        var targets = new Dictionary<string, DomainLabels>(StringComparer.OrdinalIgnoreCase);

        foreach (var record in answers)
        {
            if (record.Type is not DomainRecordType.CNAME || record.Data is not NameData nameData)
                continue;
            targets[record.Name.ToString()] = nameData.Name;
        }

        if (targets.Count == 0)
            return null;

        // Start from any owner that is not itself a target of another CNAME in the set.
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
