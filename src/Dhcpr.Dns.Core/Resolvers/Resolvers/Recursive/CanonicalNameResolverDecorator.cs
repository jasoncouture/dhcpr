using System.Collections.Immutable;

using Dhcpr.Core;
using Dhcpr.Core.Linq;
using Dhcpr.Dns.Core.Protocol;
using Dhcpr.Dns.Core.Protocol.Processing;
using Dhcpr.Dns.Core.Protocol.RecordData;

namespace Dhcpr.Dns.Core.Resolvers.Resolvers.Recursive;

public sealed class CanonicalNameResolverDecorator : IDomainMessageMiddleware
{
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

        using var cnameRecords = result.Records.Answers.ToPooledList();

        foreach (var record in cnameRecords)
        {
            if (record.Data is not NameData nameData)
                continue;

            var nextRequest = DomainMessage.CreateRequest(nameData.Name, questionType);

            var nextResponse = await _internalClient.SendAsync(context, nextRequest, cancellationToken)
                .AsTask()
                .ConvertExceptionsToNull();

            if (nextResponse is null) continue;
            if (nextResponse.Records.Answers.Length == 0) continue;

            result = result with
            {
                Records = result.Records with
                {
                    Answers = result.Records.Answers
                        .Concat(nextResponse.Records.Answers.Where(i =>
                            i.Type is DomainRecordType.CNAME || i.Type == questionType))
                        .ToImmutableArray()
                }
            };

            if (result.Records.Answers.Any(i => i.Type == questionType))
                break;
        }

        return result;
    }

    public string Name => _innerMiddleware.Name;

    public int Priority => _innerMiddleware.Priority;
}
