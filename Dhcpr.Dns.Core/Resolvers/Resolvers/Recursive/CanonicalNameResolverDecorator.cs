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
    private readonly IDomainClientFactory _clientFactory;

    public CanonicalNameResolverDecorator(IDomainMessageMiddleware innerMiddleware, IDomainClientFactory clientFactory)
    {
        this._innerMiddleware = innerMiddleware;
        _clientFactory = clientFactory;
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

        if (result.Records.All(i => i.Type != DomainRecordType.CNAME))
            return result;

        if (result.Records.Answers.Any(i => i.Type == questionType))
            return result;

        using var cnameRecords = result.Records
            .Where(i => i.Type == DomainRecordType.CNAME)
            .ToPooledList();

        var internalClient =
            await _clientFactory.GetDomainClient(new DomainClientOptions() { Type = DomainClientType.Internal },
                cancellationToken);

        foreach (var record in cnameRecords)
        {
            var targetName = ((NameData)record.Data).Name.ToString();
            var nextRequest = DomainMessage.CreateRequest(targetName, questionType);

            var nextResponse = await internalClient.SendAsync(nextRequest, cancellationToken)
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
